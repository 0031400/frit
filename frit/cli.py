"""Command line entry point: `frit server -c cfg.json` / `frit client -c cfg.json`.

The config file path comes from the command line only; no environment variables
are read.  Runs on a single asyncio event loop.

Signals: SIGINT / SIGTERM / SIGBREAK trigger an orderly shutdown.  Ctrl+C works
even on Windows under `uv run`, where the launcher may swallow the console event
for the child, because the interpreter itself registers the handler.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

from . import __version__
from .client import Client
from .config import ClientConfig, ConfigError, ServerConfig
from .server import BindError, Server

log = logging.getLogger("frit.cli")


def _setup_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _install_signal_handlers(loop: asyncio.AbstractEventLoop, on_stop) -> None:
    """Make SIGINT/SIGTERM/SIGBREAK cancel the main task for a clean shutdown."""

    def stop() -> None:
        log.info("shutdown requested")
        try:
            on_stop()
        except Exception:  # noqa: BLE001
            pass
        for task in asyncio.all_tasks(loop):
            task.cancel()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, stop)
            continue
        except (NotImplementedError, RuntimeError, ValueError, AttributeError):
            pass
        # Windows: add_signal_handler is not implemented for most signals.
        try:
            signal.signal(sig, lambda _s, _f: loop.call_soon_threadsafe(stop))
        except (ValueError, OSError):
            pass


async def _amain(mode: str, config_path: str) -> int:
    loop = asyncio.get_running_loop()

    if mode == "server":
        cfg = ServerConfig.load(config_path)
        _setup_logging(cfg.debug)
        server = Server(cfg)
        _install_signal_handlers(loop, server.shutdown)
        await server.run()
    else:
        cfg = ClientConfig.load(config_path)
        _setup_logging(cfg.debug)
        client = Client(cfg)
        _install_signal_handlers(loop, client.shutdown)
        await client.run()
    return 0


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
        return asyncio.run(_amain(args.mode, args.config))
    except asyncio.CancelledError:
        return 0
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except BindError as exc:
        print(f"startup failed: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("bye", file=sys.stderr)
        return 0
    except SystemExit as exc:
        return int(exc.code or 0)


if __name__ == "__main__":
    raise SystemExit(main())
