"""Message type constants and envelope helpers (aligned with the Go reference)."""

from __future__ import annotations

from dataclasses import dataclass, field


# --- message types ---
LOGIN_REQ = "loginReq"
LOGIN_RES = "loginRes"
CONNECT_REQ = "connectReq"
CONNECT_RES = "connectRes"
# Control-connection liveness probe: ping carries an id, pong echoes it.
PING = "ping"
PONG = "pong"


# login response codes
CODE_OK = 0
CODE_TOKEN_ERROR = 1
CODE_NAME_EXIST = 2
CODE_REMOTE_PORT_ERROR = 3
CODE_BAD_REQUEST = 4


@dataclass
class ProxyConfig:
    name: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "localIP": self.local_ip,
            "localPort": self.local_port,
            "remoteIP": self.remote_ip,
            "remotePort": self.remote_port,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ProxyConfig":
        return cls(
            name=d.get("name", ""),
            local_ip=d["localIP"],
            local_port=int(d["localPort"]),
            remote_ip=d["remoteIP"],
            remote_port=int(d["remotePort"]),
        )


@dataclass
class LoginReq:
    name: str
    proxies: list[ProxyConfig] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "type": LOGIN_REQ,
            "name": self.name,
            "proxies": [p.to_dict() for p in self.proxies],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "LoginReq":
        proxies = [ProxyConfig.from_dict(p) for p in d.get("proxies", [])]
        return cls(name=d.get("name", ""), proxies=proxies)


@dataclass
class LoginRes:
    code: int
    name: str = ""

    def to_dict(self) -> dict:
        return {"type": LOGIN_RES, "code": self.code, "name": self.name}


@dataclass
class ConnectReq:
    service_name: str
    task_id: int

    def to_dict(self) -> dict:
        return {
            "type": CONNECT_REQ,
            "service_name": self.service_name,
            "taskId": self.task_id,
        }


@dataclass
class ConnectRes:
    code: int
    task_id: int
    service_name: str
    client_name: str

    def to_dict(self) -> dict:
        return {
            "type": CONNECT_RES,
            "code": self.code,
            "taskId": self.task_id,
            "service_name": self.service_name,
            "client_name": self.client_name,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ConnectRes":
        return cls(
            code=int(d["code"]),
            task_id=int(d["taskId"]),
            service_name=d.get("service_name", ""),
            client_name=d.get("client_name", ""),
        )
