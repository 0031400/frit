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
import time

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

    def run(self) -> None:
        while True:
            try:
                self._run_session()
            except (OSError, crypto.CryptoError, protocol.ProtocolError) as exc:
                log.warning("session ended: %s", exc)
            except Exception as exc:  # noqa: BLE001
                log.exception("session error: %s", exc)
            log.info("reconnecting in %.0fs", RECONNECT_DELAY)
            time.sleep(RECONNECT_DELAY)

    def _connect_server(self) -> socket.socket:
        sock = socket.create_connection((self.cfg.server_host, self.cfg.server_port), timeout=10)
        sock.settimeout(None)
        return sock

    def _run_session(self) -> None:
        control = self._connect_server()
        try:
            login = msg.LoginReq(name=self.cfg.name, proxies=self.cfg.proxies)
            _send_control(control, self.key, login.to_dict())

            frame_type, payload = _recv_frame(control, self.key)
            if frame_type != protocol.FRAME_TYPE_CTRL:
                raise protocol.ProtocolError("login response not CTRL frame")
            res = protocol.decode_control(payload)
            code = int(res.get("code", -1))
            if code != msg.CODE_OK:
                raise OSError(f"login rejected, code={code}")
            name = res.get("name") or self.cfg.name
            log.info("login success, name=%s", name)

            while True:
                frame_type, payload = _recv_frame(control, self.key)
                if frame_type != protocol.FRAME_TYPE_CTRL:
                    raise protocol.ProtocolError("non-CTRL frame on control connection")
                d = protocol.decode_control(payload)
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
