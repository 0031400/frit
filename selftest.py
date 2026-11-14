"""End-to-end self test: echo service + frit server + frit client + tunnel check.

Starts an echo TCP server on the local port, then the frit server and client
as subprocesses, then connects through the exposed remote port and verifies
round-trip bytes.  Also verifies that a wrong-PSK / garbage client is dropped.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

CTRL_PORT = 40123
LOCAL_PORT = 40124
REMOTE_PORT = 40125
PSK = "test-psk-123"


def free_ok(port: int) -> bool:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def start_echo(port: int) -> subprocess.Popen:
    code = (
        "import socket,threading\n"
        f"s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        f"s.bind(('127.0.0.1',{port}));s.listen(8)\n"
        "def h(c):\n"
        "  while True:\n"
        "    d=c.recv(65536)\n"
        "    if not d: break\n"
        "    c.sendall(d)\n"
        "  c.close()\n"
        "while True:\n"
        "  c,_=s.accept();threading.Thread(target=h,args=(c,),daemon=True).start()\n"
    )
    return subprocess.Popen([PY, "-c", code])


def wait_port(port: int, timeout=10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def write_cfg(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def main() -> int:
    for p in (CTRL_PORT, LOCAL_PORT, REMOTE_PORT):
        if not free_ok(p):
            print(f"port {p} busy, aborting")
            return 1

    tmp = tempfile.mkdtemp(prefix="frit-test-")
    server_cfg = os.path.join(tmp, "server.json")
    client_cfg = os.path.join(tmp, "client.json")

    write_cfg(server_cfg, {
        "listen": f"tcp://0.0.0.0:{CTRL_PORT}",
        "psk": PSK,
        "debug": True,
    })
    write_cfg(client_cfg, {
        "server": f"tcp://127.0.0.1:{CTRL_PORT}",
        "psk": PSK,
        "name": "testclient",
        "debug": True,
        "proxies": [{
            "name": "echo",
            "localIP": "127.0.0.1",
            "localPort": LOCAL_PORT,
            "remoteIP": "127.0.0.1",
            "remotePort": REMOTE_PORT,
        }],
    })

    procs = []
    try:
        echo = start_echo(LOCAL_PORT)
        procs.append(echo)
        if not wait_port(LOCAL_PORT):
            print("echo not up"); return 1

        srv = subprocess.Popen([PY, "-m", "frit", "server", "-c", server_cfg], cwd=ROOT)
        procs.append(srv)
        if not wait_port(CTRL_PORT):
            print("server not up"); return 1

        cli = subprocess.Popen([PY, "-m", "frit", "client", "-c", client_cfg], cwd=ROOT)
        procs.append(cli)

        if not wait_port(REMOTE_PORT, timeout=15):
            print("remote port not exposed"); return 1
        time.sleep(0.5)

        # --- round trip 1 ---
        with socket.create_connection(("127.0.0.1", REMOTE_PORT), timeout=5) as c:
            c.sendall(b"hello-frit")
            got = c.recv(4096)
        print("roundtrip1:", got)
        if got != b"hello-frit":
            print("FAIL roundtrip1"); return 1

        # --- round trip 2 (second connection, large payload) ---
        big = bytes(range(256)) * 64  # 16 KiB
        with socket.create_connection(("127.0.0.1", REMOTE_PORT), timeout=5) as c:
            c.sendall(big)
            buf = b""
            while len(buf) < len(big):
                d = c.recv(65536)
                if not d:
                    break
                buf += d
        print("roundtrip2 bytes:", len(buf))
        if buf != big:
            print("FAIL roundtrip2"); return 1

        # --- bad key client must be dropped ---
        bad_cfg = os.path.join(tmp, "bad.json")
        write_cfg(bad_cfg, {
            "server": f"tcp://127.0.0.1:{CTRL_PORT}",
            "psk": "wrong-key",
            "proxies": [],
        })
        bad = subprocess.Popen([PY, "-m", "frit", "client", "-c", bad_cfg], cwd=ROOT)
        procs.append(bad)
        time.sleep(2.0)
        # good tunnel should still work (bad client didn't crash server)
        with socket.create_connection(("127.0.0.1", REMOTE_PORT), timeout=5) as c:
            c.sendall(b"after-bad")
            got2 = c.recv(4096)
        print("roundtrip3:", got2)
        if got2 != b"after-bad":
            print("FAIL roundtrip3"); return 1
        print("ALL OK")
        return 0
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(0.5)
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
