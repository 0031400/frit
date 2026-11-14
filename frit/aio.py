"""Asyncio frame IO and relay helpers built on top of crypto.py.

A connection here is an asyncio (StreamReader, StreamWriter) pair.  Every
read/write goes through the encrypted, length-prefixed frame format from
crypto.py; the plaintext inside a frame is a typed frame from protocol.py.

Encrypted wire format (unchanged):  [2B ciphertext len][ciphertext]
Plaintext inside:                    [2B frame type][payload]
"""

from __future__ import annotations

import asyncio
import struct

from . import crypto, protocol

_LEN_SIZE = 2


async def read_frame(reader: asyncio.StreamReader, key: bytes) -> bytes:
    """Read one encrypted frame and return its decrypted plaintext."""
    length_bytes = await reader.readexactly(_LEN_SIZE)
    (length,) = struct.unpack(">H", length_bytes)
    if length <= 0 or length % 16 != 0:
        raise crypto.CryptoError(f"invalid frame length: {length}")
    ciphertext = await reader.readexactly(length)
    return crypto.decrypt(key, ciphertext)


async def write_frame(writer: asyncio.StreamWriter, key: bytes, plaintext: bytes) -> None:
    """Encrypt plaintext and write one frame, then drain."""
    ciphertext = crypto.encrypt(key, plaintext)
    writer.write(struct.pack(">H", len(ciphertext)))
    writer.write(ciphertext)
    await writer.drain()


async def read_typed(reader: asyncio.StreamReader, key: bytes) -> tuple[int, bytes]:
    """Read one frame and split it into (frame_type, payload)."""
    return protocol.decode_frame(await read_frame(reader, key))


async def send_control(writer: asyncio.StreamWriter, key: bytes, obj: dict) -> None:
    await write_frame(writer, key, protocol.encode_control(obj))


async def send_data(writer: asyncio.StreamWriter, key: bytes, payload: bytes) -> None:
    await write_frame(writer, key, protocol.encode_frame(protocol.FRAME_TYPE_DATA, payload))


async def relay_plain_to_encrypted(
    plain_reader: asyncio.StreamReader,
    plain_writer: asyncio.StreamWriter,
    enc_reader: asyncio.StreamReader,
    enc_writer: asyncio.StreamWriter,
    key: bytes,
) -> None:
    """Bridge one plaintext peer and one encrypted peer, both directions.

    plain side  : raw bytes (external socket or local service)
    enc   side  : typed DATA frames
    Returns when either side closes/errors; both peers are then closed.
    """

    async def pump_plain_to_enc() -> None:
        while True:
            chunk = await plain_reader.read(65536)
            if not chunk:
                break
            await send_data(enc_writer, key, chunk)

    async def pump_enc_to_plain() -> None:
        while True:
            frame_type, payload = await read_typed(enc_reader, key)
            if frame_type != protocol.FRAME_TYPE_DATA:
                raise protocol.ProtocolError(f"unexpected frame {frame_type} on data connection")
            if not payload:
                break
            plain_writer.write(payload)
            await plain_writer.drain()

    tasks = [
        asyncio.create_task(pump_plain_to_enc()),
        asyncio.create_task(pump_enc_to_plain()),
    ]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        # Surface a real error (not cancellation / normal close) for logging.
        for t in done:
            exc = t.exception()
            if exc and not isinstance(
                exc, (asyncio.IncompleteReadError, ConnectionError, OSError,
                      crypto.CryptoError, protocol.ProtocolError),
            ):
                raise exc
    finally:
        _close_writer(plain_writer)
        _close_writer(enc_writer)


def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass
