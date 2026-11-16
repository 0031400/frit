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

RECONNECT_DELAY = 2.0
# The server pings every 60s; if nothing at all arrives for this long the
# control connection is considered dead and we reconnect.
CONTROL_READ_TIMEOUT = 150.0
SERVER_CONNECT_TIMEOUT = 10.0
# Must stay well below the server's 5s pairing timeout so a live client can
# still report success/failure before the external connection is dropped.
DATA_CONNECT_TIMEOUT = 3.0
LOCAL_CONNECT_TIMEOUT = 2.0


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
        self, host: str, port: int, timeout: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )

    async def _send_control(self, writer: asyncio.StreamWriter, obj: dict) -> None:
        # Each stream has a single writer (control: this loop; data: its own
        # handshake task), so no lock is needed here.
        await aio.send_control(writer, self.key, obj)

    async def _run_session(self) -> None:
        reader, writer = await self._open_connection(
            self.cfg.server_host, self.cfg.server_port, SERVER_CONNECT_TIMEOUT
        )
        self._control_writer = writer
        try:
            login = msg.LoginReq(name=self.cfg.name, proxies=self.cfg.proxies)
            await self._send_control(writer, login.to_dict())

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
                try:
                    frame_type, payload = await asyncio.wait_for(
                        aio.read_typed(reader, self.key),
                        timeout=CONTROL_READ_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    raise OSError(
                        f"no control message for {CONTROL_READ_TIMEOUT:.0f}s; reconnecting"
                    ) from None
                if frame_type != protocol.FRAME_TYPE_CTRL:
                    raise protocol.ProtocolError("non-CTRL frame on control connection")
                d = protocol.decode_control(payload)
                mtype = d.get("type")
                if mtype == msg.CONNECT_REQ:
                    task = asyncio.create_task(
                        self._handle_connect_req(
                            name, d.get("service_name", ""), int(d.get("taskId", 0))
                        )
                    )
                    self._data_tasks.add(task)
                    task.add_done_callback(self._data_tasks.discard)
                elif mtype == msg.PING:
                    await self._send_control(
                        writer, {"type": msg.PONG, "id": d.get("id")}
                    )
                else:
                    log.debug("unknown control message: %s", mtype)
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
                self.cfg.server_host, self.cfg.server_port, DATA_CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError) as exc:
            log.error("connect data channel: %s", exc)
            return

        # Dial the local service first.  If it fails, tell the server with a
        # non-zero code so it drops the pending external connection immediately
        # (instead of waiting for its 30s pairing timeout).
        try:
            local_reader, local_writer = await self._open_connection(
                proxy.local_ip, proxy.local_port, LOCAL_CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError) as exc:
            log.error("connect local %s:%d: %s", proxy.local_ip, proxy.local_port, exc)
            try:
                await self._send_control(
                    data_writer,
                    msg.ConnectRes(code=msg.CODE_BAD_REQUEST, task_id=task_id,
                                   service_name=service_name,
                                   client_name=client_name).to_dict(),
                )
            except (OSError, crypto.CryptoError):
                pass
            _close_writer(data_writer)
            return

        try:
            res = msg.ConnectRes(code=msg.CODE_OK, task_id=task_id,
                                 service_name=service_name, client_name=client_name)
            await self._send_control(data_writer, res.to_dict())
        except (OSError, crypto.CryptoError) as exc:
            log.error("send connectRes: %s", exc)
            _close_writer(local_writer)
            _close_writer(data_writer)
            return

        log.info("bridging %s -> %s:%d", service_name, proxy.local_ip, proxy.local_port)
        try:
            await aio.relay_plain_to_encrypted(
                local_reader, local_writer, data_reader, data_writer, self.key
            )
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
