"""Command line entry point: `frit server -c cfg.json` / `frit client -c cfg.json`.

The config file path comes from the command line only; no environment variables
are read.
"""

from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .client import Client
from .config import ClientConfig, ConfigError, ServerConfig
from .server import Server


def _setup_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="frit", description="frp-like TCP tunnel")
    parser.add_argument("--version", action="version", version=f"frit {__version__}")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_server = sub.add_parser("server", help="run the public-side server")
    p_server.add_argument("-c", "--config", default="config.json")

    p_client = sub.add_parser("client", help="run the internal-side client")
    p_client.add_argument("-c", "--config", default="config.json")

    args = parser.parse_args(argv)

    try:
        if args.mode == "server":
            cfg = ServerConfig.load(args.config)
            _setup_logging(cfg.debug)
            Server(cfg).run()
        else:
            cfg = ClientConfig.load(args.config)
            _setup_logging(cfg.debug)
            Client(cfg).run()
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("bye", file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
