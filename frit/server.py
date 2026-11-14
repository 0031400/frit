"""Threaded server: control connection + dynamic per-proxy listeners + relay.

Flow (mirrors the Go reference, minus the L4 handshake):

  client connects -> first (encrypted) frame must be a CTRL frame with
                     loginReq{name, proxies}; otherwise the connection is dropped
                     (this is the "authentication middleware")
  server replies loginRes over the control connection
  server opens a real TCP listener on each proxy's remoteIP:remotePort
  external client connects -> server allocates taskId -> connectReq over control
  client opens a NEW connection to the server -> first frame connectRes
  server pairs by (client_name, service_name, taskId) and relays bytes

All bytes on every connection travel inside the encrypted, typed frame format
defined in protocol.py / crypto.py.
"""

from __future__ import annotations

import logging
import socket
import threading

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
# frame helpers
# --------------------------------------------------------------------------
def _safe_close(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _recv_frame(sock: socket.socket, key: bytes) -> tuple[int, bytes]:
    return protocol.decode_frame(crypto.read_frame(sock.makefile("rb", buffering=0), key))


def _send_control(sock: socket.socket, key: bytes, obj: dict, lock: threading.Lock) -> None:
    payload = protocol.encode_control(obj)
    with lock:
        crypto.write_frame(sock.makefile("wb", buffering=0), key, payload)


def _relay_encrypted(plain: socket.socket, data: socket.socket, key: bytes) -> None:
    """Bridge a plaintext peer (`plain`) and an encrypted data connection (`data`)."""
    done = threading.Event()

    def plain_to_data() -> None:
        try:
            w = data.makefile("wb", buffering=0)
            while True:
                buff = plain.recv(65536)
                if not buff:
                    break
                crypto.write_frame(w, key, protocol.encode_frame(protocol.FRAME_TYPE_DATA, buff))
        except (OSError, crypto.CryptoError, protocol.ProtocolError):
            pass
        finally:
            done.set()

    def data_to_plain() -> None:
        try:
            r = data.makefile("rb", buffering=0)
            while True:
                frame_type, payload = protocol.decode_frame(crypto.read_frame(r, key))
                if frame_type != protocol.FRAME_TYPE_DATA:
                    break  # only data frames are valid on a data connection
                if not payload:
                    break
                plain.sendall(payload)
        except (OSError, crypto.CryptoError, protocol.ProtocolError):
            pass
        finally:
            done.set()

    threading.Thread(target=plain_to_data, daemon=True).start()
    threading.Thread(target=data_to_plain, daemon=True).start()
    done.wait()
    _safe_close(plain)
    _safe_close(data)


# --------------------------------------------------------------------------
# model
# --------------------------------------------------------------------------
class _Service:
    def __init__(self, name: str, sock: socket.socket, key: bytes):
        self.name = name
        self.sock = sock
        self.key = key
        self._lock = threading.Lock()
        self._task_id = 0
        self._sessions: dict[int, socket.socket] = {}

    def next_task_id(self) -> int:
        with self._lock:
            self._task_id += 1
            return self._task_id

    def add_session(self, task_id: int, conn: socket.socket) -> None:
        with self._lock:
            self._sessions[task_id] = conn

    def pop_session(self, task_id: int) -> socket.socket | None:
        with self._lock:
            return self._sessions.pop(task_id, None)

    def close_all(self) -> None:
        _safe_close(self.sock)
        with self._lock:
            for conn in self._sessions.values():
                _safe_close(conn)
            self._sessions.clear()


class _Client:
    def __init__(self, name: str, control: socket.socket, key: bytes):
        self.name = name
        self.control = control
        self.key = key
        self._lock = threading.RLock()
        self._services: dict[str, _Service] = {}
        self._write_lock = threading.Lock()

    def add_service(self, service: _Service) -> None:
        with self._lock:
            self._services[service.name] = service

    def get_service(self, name: str) -> _Service | None:
        with self._lock:
            return self._services.get(name)

    def all_services(self) -> list[_Service]:
        with self._lock:
            return list(self._services.values())

    def send(self, obj: dict) -> None:
        _send_control(self.control, self.key, obj, self._write_lock)

    def close_all(self) -> None:
        for svc in self.all_services():
            svc.close_all()
        _safe_close(self.control)


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------
class Server:
    def __init__(self, cfg: ServerConfig):
        self.cfg = cfg
        self.key = crypto.derive_key(cfg.psk)
        self._lock = threading.RLock()
        self._clients: dict[str, _Client] = {}

    def run(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.cfg.host, self.cfg.port))
        except OSError as exc:
            log.error(
                "cannot bind tcp://%s:%d (%s). The port may already be in use.",
                self.cfg.host, self.cfg.port, exc,
            )
            srv.close()
            raise BindError(self.cfg.host, self.cfg.port, exc) from exc
        srv.listen(128)
        # A short accept timeout lets the loop observe self._stop promptly, so a
        # signal handler (see cli.py) can shut the server down cleanly even while
        # accept() is waiting.
        srv.settimeout(0.5)
        self._stop = threading.Event()
        log.info("listen on tcp://%s:%d", self.cfg.host, self.cfg.port)
        try:
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            log.info("interrupted, shutting down")
        finally:
            self._stop.set()
            try:
                srv.close()
            except OSError:
                pass
            for client in self._all_clients():
                client.close_all()

    def shutdown(self) -> None:
        """Ask the accept loop to stop and tear down all client connections."""
        stop = getattr(self, "_stop", None)
        if stop is not None:
            stop.set()

    def _all_clients(self) -> list["_Client"]:
        with self._lock:
            return list(self._clients.values())

    # -- first-frame dispatch (the auth middleware) ------------------------
    def _handle(self, conn: socket.socket, addr) -> None:
        try:
            frame_type, payload = _recv_frame(conn, self.key)
            if frame_type != protocol.FRAME_TYPE_CTRL:
                raise protocol.ProtocolError(f"first frame not CTRL ({frame_type})")
            first = protocol.decode_control(payload)
        except Exception as exc:  # noqa: BLE001 - drop anything that fails
            log.warning("reject %s: %s", addr, exc)
            _safe_close(conn)
            return

        mtype = first.get("type")
        if mtype == msg.LOGIN_REQ:
            self._handle_login(conn, first)
        elif mtype == msg.CONNECT_RES:
            self._handle_connect_res(conn, first)
        else:
            log.warning("reject %s: unknown first message %r", addr, mtype)
            _safe_close(conn)

    def _handle_login(self, conn: socket.socket, d: dict) -> None:
        try:
            req = msg.LoginReq.from_dict(d)
        except (KeyError, TypeError, ValueError) as exc:
            self._send_safe(conn, msg.LoginRes(code=msg.CODE_BAD_REQUEST).to_dict())
            log.warning("bad login request: %s", exc)
            _safe_close(conn)
            return

        with self._lock:
            if not req.name:
                req.name = self._new_name_locked()
            if req.name in self._clients:
                self._send_safe(conn, msg.LoginRes(code=msg.CODE_NAME_EXIST).to_dict())
                log.warning("client name exists: %s", req.name)
                _safe_close(conn)
                return

            client = _Client(req.name, conn, self.key)
            created: list[_Service] = []
            try:
                for proxy in req.proxies:
                    svc = self._open_service(req.name, proxy)
                    client.add_service(svc)
                    created.append(svc)
            except OSError as exc:
                for svc in created:
                    svc.close_all()
                self._send_safe(conn, msg.LoginRes(code=msg.CODE_REMOTE_PORT_ERROR).to_dict())
                log.error(
                    "cannot expose proxy for client %s: port %s:%d may be in use (%s); "
                    "rejecting login",
                    req.name, proxy.remote_ip, proxy.remote_port, exc,
                )
                _safe_close(conn)
                return

            self._clients[req.name] = client

        self._send_safe(conn, msg.LoginRes(code=msg.CODE_OK, name=req.name).to_dict())
        log.info("client logged in: name=%s proxies=%d", req.name, len(req.proxies))

        for svc in client.all_services():
            threading.Thread(target=self._accept_service, args=(client, svc), daemon=True).start()

        self._read_control(conn, req.name)

    def _open_service(self, client_name: str, proxy) -> _Service:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((proxy.remote_ip, proxy.remote_port))
        s.listen(128)
        log.info("service %s/%s listening on %s:%d",
                 client_name, proxy.name, proxy.remote_ip, proxy.remote_port)
        return _Service(proxy.name, s, self.key)

    def _read_control(self, conn: socket.socket, client_name: str) -> None:
        try:
            while True:
                frame_type, payload = _recv_frame(conn, self.key)
                if frame_type != protocol.FRAME_TYPE_CTRL:
                    raise protocol.ProtocolError("non-CTRL frame on control connection")
                d = protocol.decode_control(payload)
                log.debug("control %s: %s", client_name, d.get("type"))
        except Exception as exc:  # noqa: BLE001
            log.info("control closed for %s: %s", client_name, exc)
        finally:
            self._remove_client(client_name, conn)

    def _remove_client(self, client_name: str, conn: socket.socket) -> None:
        with self._lock:
            client = self._clients.get(client_name)
            if client is None or client.control is not conn:
                return
            del self._clients[client_name]
        client.close_all()
        log.info("client removed: %s", client_name)

    def _accept_service(self, client: _Client, service: _Service) -> None:
        while True:
            try:
                external, addr = service.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle_external,
                             args=(client, service, external, addr), daemon=True).start()

    def _handle_external(self, client: _Client, service: _Service, external, addr) -> None:
        task_id = service.next_task_id()
        service.add_session(task_id, external)
        log.info("external %s -> %s/%s task=%d", addr, client.name, service.name, task_id)
        try:
            client.send(msg.ConnectReq(service_name=service.name, task_id=task_id).to_dict())
        except (OSError, crypto.CryptoError) as exc:
            log.error("send connectReq failed: %s", exc)
            service.pop_session(task_id)
            _safe_close(external)

    def _handle_connect_res(self, conn: socket.socket, d: dict) -> None:
        try:
            res = msg.ConnectRes.from_dict(d)
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("bad connectRes: %s", exc)
            _safe_close(conn)
            return

        if res.code != msg.CODE_OK:
            log.warning("client rejected task %d (code=%d)", res.task_id, res.code)
            _safe_close(conn)
            return

        with self._lock:
            client = self._clients.get(res.client_name)
        if client is None:
            log.warning("connectRes for unknown client: %s", res.client_name)
            _safe_close(conn)
            return
        service = client.get_service(res.service_name)
        if service is None:
            log.warning("connectRes for unknown service: %s", res.service_name)
            _safe_close(conn)
            return
        external = service.pop_session(res.task_id)
        if external is None:
            log.warning("connectRes for unknown task: %d", res.task_id)
            _safe_close(conn)
            return

        log.debug("task %d paired, relaying", res.task_id)
        _relay_encrypted(external, conn, self.key)

    def _new_name_locked(self) -> str:
        i = 1
        while f"client{i:02d}" in self._clients:
            i += 1
        return f"client{i:02d}"

    def _send_safe(self, conn: socket.socket, obj: dict) -> None:
        try:
            crypto.write_frame(conn.makefile("wb", buffering=0), self.key,
                               protocol.encode_control(obj))
        except (OSError, crypto.CryptoError):
            pass
