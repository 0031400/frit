"""Client: keep a control connection to the server, answer connectReq by
opening a fresh data connection and bridging it to the local service.

Flow (mirrors the Go reference, minus the L4 handshake):

  connect to server -> send CTRL loginReq{name, proxies} -> read loginRes{code}
  loop reading control messages:
    connectReq{service_name, taskId} -> open NEW connection to server
        -> send CTRL connectRes{code, taskId, service_name, client_name}
        -> dial localIP:localPort -> relay DATA frames with the server
  on any control disconnect: reconnect after a delay and re-login.
"""

from __future__ import annotations

import logging
import socket
import threading

from . import crypto
from . import message as msg
from . import protocol
from .config import ClientConfig

log = logging.getLogger("frit.client")

RECONNECT_DELAY = 5.0


def _safe_close(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _recv_frame(sock: socket.socket, key: bytes) -> tuple[int, bytes]:
    return protocol.decode_frame(crypto.read_frame(sock.makefile("rb", buffering=0), key))


def _send_control(sock: socket.socket, key: bytes, obj: dict) -> None:
    crypto.write_frame(sock.makefile("wb", buffering=0), key, protocol.encode_control(obj))


def _relay_encrypted(local: socket.socket, data: socket.socket, key: bytes) -> None:
    """Bridge a plaintext local service socket with the encrypted data connection."""
    done = threading.Event()

    def local_to_data() -> None:
        try:
            w = data.makefile("wb", buffering=0)
            while True:
                buff = local.recv(65536)
                if not buff:
                    break
                crypto.write_frame(w, key, protocol.encode_frame(protocol.FRAME_TYPE_DATA, buff))
        except (OSError, crypto.CryptoError, protocol.ProtocolError):
            pass
        finally:
            done.set()

    def data_to_local() -> None:
        try:
            r = data.makefile("rb", buffering=0)
            while True:
                frame_type, payload = protocol.decode_frame(crypto.read_frame(r, key))
                if frame_type != protocol.FRAME_TYPE_DATA:
                    break
                if not payload:
                    break
                local.sendall(payload)
        except (OSError, crypto.CryptoError, protocol.ProtocolError):
            pass
        finally:
            done.set()

    threading.Thread(target=local_to_data, daemon=True).start()
    threading.Thread(target=data_to_local, daemon=True).start()
    done.wait()
    _safe_close(local)
    _safe_close(data)


class Client:
    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self.key = crypto.derive_key(cfg.psk)
        self._proxies = {p.name: p for p in cfg.proxies}
        self._stop = threading.Event()
        self._control: socket.socket | None = None

    def shutdown(self) -> None:
        """Request the run loop to stop and close the control connection."""
        self._stop.set()
        _safe_close(self._control)
        self._control = None

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self._run_session()
            except (OSError, crypto.CryptoError, protocol.ProtocolError) as exc:
                log.warning("session ended: %s", exc)
            except Exception as exc:  # noqa: BLE001
                log.exception("session error: %s", exc)
            if self._stop.is_set():
                break
            log.info("reconnecting in %.0fs", RECONNECT_DELAY)
            # Interruptible sleep so shutdown()/Ctrl+C is honoured promptly.
            if self._stop.wait(RECONNECT_DELAY):
                break
        log.info("client stopped")

    def _connect_server(self) -> socket.socket:
        sock = socket.create_connection((self.cfg.server_host, self.cfg.server_port), timeout=10)
        sock.settimeout(0.5)
        return sock

    def _run_session(self) -> None:
        control = self._connect_server()
        self._control = control
        try:
            login = msg.LoginReq(name=self.cfg.name, proxies=self.cfg.proxies)
            _send_control(control, self.key, login.to_dict())

            res = self._recv_control_until(control)
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

            while not self._stop.is_set():
                d = self._recv_control_until(control)
                if d is None:
                    return
                if d.get("type") == msg.CONNECT_REQ:
                    threading.Thread(
                        target=self._handle_connect_req,
                        args=(name, d.get("service_name", ""), int(d.get("taskId", 0))),
                        daemon=True,
                    ).start()
                else:
                    log.debug("unknown control message: %s", d.get("type"))
        finally:
            _safe_close(control)
            if self._control is control:
                self._control = None

    def _recv_control_until(self, control: socket.socket) -> dict | None:
        """Read one control frame, polling so a pending shutdown is honoured."""
        while not self._stop.is_set():
            try:
                frame_type, payload = _recv_frame(control, self.key)
            except socket.timeout:
                continue
            except (OSError, crypto.CryptoError):
                if self._stop.is_set():
                    return None
                raise
            if frame_type != protocol.FRAME_TYPE_CTRL:
                raise protocol.ProtocolError("non-CTRL frame on control connection")
            return protocol.decode_control(payload)
        return None

    def _handle_connect_req(self, client_name: str, service_name: str, task_id: int) -> None:
        proxy = self._proxies.get(service_name)
        if proxy is None:
            log.warning("connectReq for unknown proxy: %s", service_name)
            return

        try:
            data = self._connect_server()
        except OSError as exc:
            log.error("connect data channel: %s", exc)
            return
        # Data connections relay raw bytes; use blocking mode (no 0.5s timeout).
        data.settimeout(None)

        try:
            res = msg.ConnectRes(code=msg.CODE_OK, task_id=task_id,
                                 service_name=service_name, client_name=client_name)
            _send_control(data, self.key, res.to_dict())
        except (OSError, crypto.CryptoError) as exc:
            log.error("send connectRes: %s", exc)
            _safe_close(data)
            return

        try:
            local = socket.create_connection((proxy.local_ip, proxy.local_port), timeout=10)
            local.settimeout(None)
        except OSError as exc:
            log.error("connect local %s:%d: %s", proxy.local_ip, proxy.local_port, exc)
            _safe_close(data)
            return

        log.info("bridging %s -> %s:%d", service_name, proxy.local_ip, proxy.local_port)
        _relay_encrypted(local, data, self.key)
