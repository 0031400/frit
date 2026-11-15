"""Asyncio server: control connection + dynamic per-proxy listeners + relay.

Flow (mirrors the Go reference, minus the L4 handshake):

  client connects -> first (encrypted) frame must be a CTRL frame with
                     loginReq{name, proxies}; otherwise it is dropped
                     (this is the "authentication middleware")
  server replies loginRes over the control connection
  server opens a real TCP listener on each proxy's remoteIP:remotePort
  external client connects -> server allocates taskId -> connectReq over control
  client opens a NEW connection to the server -> first frame connectRes
  server pairs by (client_name, service_name, taskId) and relays bytes

All bytes on every connection travel inside the encrypted, typed frame format
defined in protocol.py / crypto.py.  The whole thing is a single-event-loop
asyncio program (no threads).
"""

from __future__ import annotations

import asyncio
import logging
import socket
import sys

from . import aio
from . import crypto
from . import message as msg
from . import protocol
from .config import ServerConfig

log = logging.getLogger("frit.server")


class BindError(Exception):
    """Raised when the main listen address cannot be bound."""

    def __init__(self, host: str, port: int, cause: OSError):
        self.host = host
        self.port = port
        self.cause = cause
        super().__init__(f"cannot bind tcp://{host}:{port}: {cause}")


# --------------------------------------------------------------------------
# listener creation (cross-platform port semantics)
# --------------------------------------------------------------------------
def make_listen_socket(host: str, port: int, backlog: int = 128) -> socket.socket:
    """Create a TCP listening socket with platform-aware port semantics.

    - Windows: SO_EXCLUSIVEADDRUSE so the port is exclusive; bind() fails if
      another process is listening on the same address:port.  (Restarting may
      briefly fail while the port is still in TIME_WAIT.)
    - POSIX: SO_REUSEADDR so a port in TIME_WAIT can be rebound (fast restart),
      while bind() still fails against an actively listening socket.

    The socket is returned already bound+listening, and can be handed to
    loop.create_server(sock=...).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(backlog)
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise
    return sock


def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass


# task ids are allocated per service and wrapped around at this cap so the
# counter never grows without bound on a long-running server.  Any id still
# in-flight is skipped during allocation.
_TASK_ID_MAX = 0x7FFFFFFF

# How long the server waits for the client to answer a connectReq with a
# connectRes before giving up on that external connection.  Prevents leaked
# sessions if the client is slow / stuck / the notification is lost.
PENDING_CONNECT_TIMEOUT = 30.0


class _Pending:
    """A not-yet-paired external connection awaiting the client's data conn."""

    __slots__ = ("reader", "writer", "future")

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        # Resolved with the paired (reader, writer) of the client data conn.
        self.future: asyncio.Future[
            tuple[asyncio.StreamReader, asyncio.StreamWriter] | None
        ] = asyncio.get_running_loop().create_future()


# --------------------------------------------------------------------------
# model
# --------------------------------------------------------------------------
class _Service:
    def __init__(self, name: str, server: asyncio.AbstractServer | None):
        self.name = name
        self.server = server
        self._task_id = 0
        # task_id -> _Pending (external peer waiting for the client data conn)
        self._sessions: dict[int, _Pending] = {}

    def next_task_id(self) -> int:
        # Wrap around and skip ids that are still in flight.
        for _ in range(len(self._sessions) + 1):
            self._task_id = self._task_id % _TASK_ID_MAX + 1
            if self._task_id not in self._sessions:
                return self._task_id
        # Extremely unlikely (all ids busy); still return a unique-ish id.
        return self._task_id

    def add_session(
        self,
        task_id: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> _Pending:
        pending = _Pending(reader, writer)
        self._sessions[task_id] = pending
        return pending

    def pop_session(self, task_id: int) -> _Pending | None:
        return self._sessions.pop(task_id, None)

    def close(self) -> None:
        if self.server is not None:
            self.server.close()
        for pending in self._sessions.values():
            _close_writer(pending.writer)
            if not pending.future.done():
                pending.future.set_result(None)
        self._sessions.clear()


class _Client:
    def __init__(self, name: str, control: asyncio.StreamWriter, key: bytes):
        self.name = name
        self.control = control
        self.key = key
        self.services: dict[str, _Service] = {}
        self._write_lock = asyncio.Lock()

    async def send(self, obj: dict) -> None:
        async with self._write_lock:
            await aio.send_control(self.control, self.key, obj)

    def close(self) -> None:
        for svc in self.services.values():
            svc.close()
        _close_writer(self.control)


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------
class Server:
    def __init__(self, cfg: ServerConfig):
        self.cfg = cfg
        self.key = crypto.derive_key(cfg.psk)
        self.clients: dict[str, _Client] = {}
        self._main_server: asyncio.AbstractServer | None = None
        self._stop = False

    async def run(self) -> None:
        try:
            sock = make_listen_socket(self.cfg.host, self.cfg.port)
        except OSError as exc:
            log.error(
                "cannot bind tcp://%s:%d (%s). The port may already be in use.",
                self.cfg.host, self.cfg.port, exc,
            )
            raise BindError(self.cfg.host, self.cfg.port, exc) from exc

        self._main_server = await asyncio.start_server(
            self._handle, sock=sock
        )
        log.info("listen on tcp://%s:%d", self.cfg.host, self.cfg.port)
        try:
            async with self._main_server:
                await self._main_server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            self._stop = True
            for client in list(self.clients.values()):
                client.close()
            self.clients.clear()

    def shutdown(self) -> None:
        """Ask the running loop to stop (call via loop.call_soon_threadsafe)."""
        self._stop = True
        if self._main_server is not None:
            self._main_server.close()

    # -- first-frame dispatch (the auth middleware) ------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            frame_type, payload = await asyncio.wait_for(
                aio.read_typed(reader, self.key), timeout=15
            )
            if frame_type != protocol.FRAME_TYPE_CTRL:
                raise protocol.ProtocolError(f"first frame not CTRL ({frame_type})")
            first = protocol.decode_control(payload)
        except Exception as exc:  # noqa: BLE001 - drop anything that fails
            log.warning("reject %s: %s", peer, exc)
            _close_writer(writer)
            return

        mtype = first.get("type")
        if mtype == msg.LOGIN_REQ:
            await self._handle_login(reader, writer, first)
        elif mtype == msg.CONNECT_RES:
            await self._handle_connect_res(reader, writer, first)
        else:
            log.warning("reject %s: unknown first message %r", peer, mtype)
            _close_writer(writer)

    async def _handle_login(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, d: dict
    ) -> None:
        try:
            req = msg.LoginReq.from_dict(d)
        except (KeyError, TypeError, ValueError) as exc:
            await self._send_safe(writer, msg.LoginRes(code=msg.CODE_BAD_REQUEST).to_dict())
            log.warning("bad login request: %s", exc)
            _close_writer(writer)
            return

        if not req.name:
            req.name = self._new_name()
        if req.name in self.clients:
            await self._send_safe(writer, msg.LoginRes(code=msg.CODE_NAME_EXIST).to_dict())
            log.warning("client name exists: %s", req.name)
            _close_writer(writer)
            return

        # Reject duplicate proxy names inside a single login (Go checks this).
        seen: set[str] = set()
        for proxy in req.proxies:
            if not proxy.name or proxy.name in seen:
                await self._send_safe(writer, msg.LoginRes(code=msg.CODE_BAD_REQUEST).to_dict())
                log.warning("duplicate/empty proxy name in login for %s", req.name)
                _close_writer(writer)
                return
            seen.add(proxy.name)

        client = _Client(req.name, writer, self.key)
        created: list[_Service] = []
        failure: tuple[str, int, OSError] | None = None
        for proxy in req.proxies:
            try:
                svc = await self._open_service(client, proxy)
            except OSError as exc:
                failure = (proxy.remote_ip, proxy.remote_port, exc)
                break
            client.services[proxy.name] = svc
            created.append(svc)

        if failure is not None:
            bad_ip, bad_port, failed_exc = failure
            for svc in created:
                svc.close()
            await self._send_safe(writer, msg.LoginRes(code=msg.CODE_REMOTE_PORT_ERROR).to_dict())
            log.error(
                "cannot expose proxy for client %s: port %s:%d may be in use (%s); "
                "rejecting login",
                req.name, bad_ip, bad_port, failed_exc,
            )
            _close_writer(writer)
            return

        self.clients[req.name] = client
        await self._send_safe(writer, msg.LoginRes(code=msg.CODE_OK, name=req.name).to_dict())
        log.info("client logged in: name=%s proxies=%d", req.name, len(req.proxies))

        try:
            while not self._stop:
                frame_type, payload = await aio.read_typed(reader, self.key)
                if frame_type != protocol.FRAME_TYPE_CTRL:
                    raise protocol.ProtocolError("non-CTRL frame on control connection")
                ctrl = protocol.decode_control(payload)
                log.debug("control %s: %s", req.name, ctrl.get("type"))
        except Exception as exc:  # noqa: BLE001
            log.info("control closed for %s: %s", req.name, exc)
        finally:
            self._remove_client(req.name, writer)

    async def _open_service(self, client: _Client, proxy) -> _Service:
        sock = make_listen_socket(proxy.remote_ip, proxy.remote_port)

        service = _Service(proxy.name, None)

        async def on_conn(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            await self._handle_external(client, service, r, w)

        server = await asyncio.start_server(on_conn, sock=sock)
        service.server = server
        log.info("service %s/%s listening on %s:%d",
                 client.name, proxy.name, proxy.remote_ip, proxy.remote_port)
        return service

    def _remove_client(self, client_name: str, writer: asyncio.StreamWriter) -> None:
        client = self.clients.get(client_name)
        if client is None or client.control is not writer:
            return
        del self.clients[client_name]
        client.close()
        log.info("client removed: %s", client_name)

    async def _handle_external(
        self,
        client: _Client,
        service: _Service,
        external_reader: asyncio.StreamReader,
        external_writer: asyncio.StreamWriter,
    ) -> None:
        peer = external_writer.get_extra_info("peername")
        task_id = service.next_task_id()
        pending = service.add_session(task_id, external_reader, external_writer)
        log.info("external %s -> %s/%s task=%d", peer, client.name, service.name, task_id)
        try:
            await client.send(
                msg.ConnectReq(service_name=service.name, task_id=task_id).to_dict()
            )
        except (OSError, crypto.CryptoError) as exc:
            log.error("send connectReq failed: %s", exc)
            service.pop_session(task_id)
            _close_writer(external_writer)
            if not pending.future.done():
                pending.future.cancel()
            return

        # Wait for the client to open its data connection and report back.
        # If it never arrives, drop the external connection so it does not leak.
        try:
            await asyncio.wait_for(asyncio.shield(pending.future), PENDING_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            log.warning(
                "task %d (%s/%s) not paired within %.0fs, dropping external %s",
                task_id, client.name, service.name, PENDING_CONNECT_TIMEOUT, peer,
            )
            service.pop_session(task_id)
            _close_writer(external_writer)
            if not pending.future.done():
                pending.future.cancel()
        except asyncio.CancelledError:
            service.pop_session(task_id)
            _close_writer(external_writer)
            raise

    async def _handle_connect_res(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, d: dict
    ) -> None:
        try:
            res = msg.ConnectRes.from_dict(d)
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("bad connectRes: %s", exc)
            _close_writer(writer)
            return

        if res.code != msg.CODE_OK:
            log.warning("client rejected task %d (code=%d)", res.task_id, res.code)
            # Drop the pending external connection immediately instead of
            # letting it sit until the pairing timeout.
            client = self.clients.get(res.client_name)
            if client is not None:
                service = client.services.get(res.service_name)
                if service is not None:
                    pending = service.pop_session(res.task_id)
                    if pending is not None:
                        _close_writer(pending.writer)
                        if not pending.future.done():
                            pending.future.cancel()
            _close_writer(writer)
            return

        client = self.clients.get(res.client_name)
        if client is None:
            log.warning("connectRes for unknown client: %s", res.client_name)
            _close_writer(writer)
            return
        service = client.services.get(res.service_name)
        if service is None:
            log.warning("connectRes for unknown service: %s", res.service_name)
            _close_writer(writer)
            return
        pending = service.pop_session(res.task_id)
        if pending is None:
            log.warning("connectRes for unknown task: %d", res.task_id)
            _close_writer(writer)
            return

        # Tell the waiting external handler that pairing succeeded, then relay.
        if not pending.future.done():
            pending.future.set_result((reader, writer))
        log.debug("task %d paired, relaying", res.task_id)
        # The external side is a plaintext socket (raw bytes); the client data
        # connection carries encrypted DATA frames.
        try:
            await aio.relay_plain_to_encrypted(
                pending.reader, pending.writer, reader, writer, self.key
            )
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass

    def _new_name(self) -> str:
        i = 1
        while f"client{i:02d}" in self.clients:
            i += 1
        return f"client{i:02d}"

    async def _send_safe(self, writer: asyncio.StreamWriter, obj: dict) -> None:
        try:
            await aio.send_control(writer, self.key, obj)
        except (OSError, crypto.CryptoError):
            pass
