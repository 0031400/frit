"""Config loading and validation for server and client.

Configuration is read only from the file path given on the command line.
No environment variables are consulted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .message import ProxyConfig


class ConfigError(Exception):
    pass


def _load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid json in {path}: {exc}") from exc


def parse_url(url: str) -> tuple[str, str, int]:
    """Parse 'tcp://host:port' into (scheme, host, port)."""
    u = urlparse(url)
    if u.scheme != "tcp":
        raise ConfigError(f"only tcp scheme is supported, got: {url!r}")
    if not u.hostname or not u.port:
        raise ConfigError(f"invalid address (need host and port): {url!r}")
    return u.scheme, u.hostname, u.port


def _as_bool(value, default: bool = False) -> bool:
    if value is None:
        return default
    return bool(value)


@dataclass
class ServerConfig:
    listen: str
    psk: str
    debug: bool = False
    host: str = ""
    port: int = 0

    @classmethod
    def load(cls, path: str) -> "ServerConfig":
        d = _load_json(path)
        if not d.get("listen"):
            raise ConfigError("server config: 'listen' is required")
        if not d.get("psk"):
            raise ConfigError("server config: 'psk' is required")
        _, host, port = parse_url(d["listen"])
        return cls(
            listen=d["listen"],
            psk=d["psk"],
            debug=_as_bool(d.get("debug", False)),
            host=host,
            port=port,
        )


@dataclass
class ClientConfig:
    server: str
    psk: str
    name: str = ""
    debug: bool = False
    proxies: list[ProxyConfig] = field(default_factory=list)
    server_host: str = ""
    server_port: int = 0

    @classmethod
    def load(cls, path: str) -> "ClientConfig":
        d = _load_json(path)
        if not d.get("server"):
            raise ConfigError("client config: 'server' is required")
        if not d.get("psk"):
            raise ConfigError("client config: 'psk' is required")
        _, host, port = parse_url(d["server"])
        proxies = [ProxyConfig.from_dict(p) for p in d.get("proxies", [])]
        for p in proxies:
            if not p.name:
                raise ConfigError("client config: proxy 'name' is required")
            if not (0 < p.local_port <= 65535 and 0 < p.remote_port <= 65535):
                raise ConfigError(f"client config: proxy {p.name!r} has invalid port")
        return cls(
            server=d["server"],
            psk=d["psk"],
            name=d.get("name", ""),
            debug=_as_bool(d.get("debug", False)),
            proxies=proxies,
            server_host=host,
            server_port=port,
        )
