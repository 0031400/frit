"""Asyncio client: keep a control connection to the server, answer connectReq by
opening a fresh data connection and bridging it to the local service.

Flow (mirrors the Go reference, minus the L4 handshake):

  connect to server -> send CTRL loginReq{name, proxies} -> read loginRes{code}
  loop reading control messages:
    connectReq{service_name, taskId} -> open NEW connection to server
        -> send CTRL connectRes{code, taskId, service_name, client_name}
        -> dial localIP:localPort -> relay DATA frames with the server
  on any control disconnect: reconnect after a delay and re-login.

Single-event-loop asyncio; each data connection is its own task.
"""

from __future__ import annotations

import asyncio
import logging

from . import aio
from . import crypto
from . import message as msg
from . import protocol
from .config import ClientConfig

log = logging.getLogger("frit.client")

RECONNECT_DELAY = 5.0


def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass


class Client:
    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self.key = crypto.derive_key(cfg.psk)
        self._proxies = {p.name: p for p in cfg.proxies}
        self._stop = False
        self._control_writer: asyncio.StreamWriter | None = None
        self._data_tasks: set[asyncio.Task] = set()

    def shutdown(self) -> None:
        """Request the run loop to stop and drop the control connection."""
        self._stop = True
        _close_writer(self._control_writer)

    async def run(self) -> None:
        while not self._stop:
            try:
                await self._run_session()
            except asyncio.CancelledError:
                break
            except (OSError, crypto.CryptoError, protocol.ProtocolError) as exc:
                if not self._stop:
                    log.warning("session ended: %s", exc)
            except Exception as exc:  # noqa: BLE001
                if not self._stop:
                    log.exception("session error: %s", exc)
            if self._stop:
                break
            log.info("reconnecting in %.0fs", RECONNECT_DELAY)
            try:
                await asyncio.sleep(RECONNECT_DELAY)
            except asyncio.CancelledError:
                break
        # Wait for in-flight data tasks to finish closing.
        if self._data_tasks:
            await asyncio.gather(*self._data_tasks, return_exceptions=True)
        log.info("client stopped")

    async def _open_connection(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )

    async def _run_session(self) -> None:
        reader, writer = await self._open_connection(
            self.cfg.server_host, self.cfg.server_port
        )
        self._control_writer = writer
        try:
            login = msg.LoginReq(name=self.cfg.name, proxies=self.cfg.proxies)
            await aio.send_control(writer, self.key, login.to_dict())

            frame_type, payload = await asyncio.wait_for(
                aio.read_typed(reader, self.key), timeout=15
            )
            if frame_type != protocol.FRAME_TYPE_CTRL:
                raise protocol.ProtocolError("login response not CTRL frame")
            res = protocol.decode_control(payload)
            code = int(res.get("code", -1))
            if code != msg.CODE_OK:
                reason = {
                    msg.CODE_TOKEN_ERROR: "authentication failed (bad psk)",
                    msg.CODE_NAME_EXIST: "client name already exists",
                    msg.CODE_REMOTE_PORT_ERROR: "a remote proxy port is in use on the server",
                    msg.CODE_BAD_REQUEST: "bad request",
                }.get(code, "unknown error")
                raise OSError(f"login rejected, code={code} ({reason})")
            name = res.get("name") or self.cfg.name
            log.info("login success, name=%s", name)

            while not self._stop:
                frame_type, payload = await aio.read_typed(reader, self.key)
                if frame_type != protocol.FRAME_TYPE_CTRL:
                    raise protocol.ProtocolError("non-CTRL frame on control connection")
                d = protocol.decode_control(payload)
                if d.get("type") == msg.CONNECT_REQ:
                    task = asyncio.create_task(
                        self._handle_connect_req(
                            name, d.get("service_name", ""), int(d.get("taskId", 0))
                        )
                    )
                    self._data_tasks.add(task)
                    task.add_done_callback(self._data_tasks.discard)
                else:
                    log.debug("unknown control message: %s", d.get("type"))
        finally:
            _close_writer(writer)
            if self._control_writer is writer:
                self._control_writer = None

    async def _handle_connect_req(
        self, client_name: str, service_name: str, task_id: int
    ) -> None:
        proxy = self._proxies.get(service_name)
        if proxy is None:
            log.warning("connectReq for unknown proxy: %s", service_name)
            return

        try:
            data_reader, data_writer = await self._open_connection(
                self.cfg.server_host, self.cfg.server_port
            )
        except OSError as exc:
            log.error("connect data channel: %s", exc)
            return

        try:
            res = msg.ConnectRes(code=msg.CODE_OK, task_id=task_id,
                                 service_name=service_name, client_name=client_name)
            await aio.send_control(data_writer, self.key, res.to_dict())
        except (OSError, crypto.CryptoError) as exc:
            log.error("send connectRes: %s", exc)
            _close_writer(data_writer)
            return

        try:
            local_reader, local_writer = await self._open_connection(
                proxy.local_ip, proxy.local_port
            )
        except OSError as exc:
            log.error("connect local %s:%d: %s", proxy.local_ip, proxy.local_port, exc)
            _close_writer(data_writer)
            return

        log.info("bridging %s -> %s:%d", service_name, proxy.local_ip, proxy.local_port)
        try:
            await aio.relay_plain_to_encrypted(
                local_reader, local_writer, data_reader, data_writer, self.key
            )
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
