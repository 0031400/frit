"""Plaintext frame codec.

A plaintext frame is:

    [2 byte big-endian frame type][payload]

The two frame-type values are randomly generated constants (not the trivially
guessable 1 / 2).  Any decrypted first frame whose type is neither of them is
dropped and the connection is closed -- this is the "authentication middleware".

Frame types:
    FRAME_TYPE_CTRL  -> payload is a JSON control message
    FRAME_TYPE_DATA  -> payload is raw relay bytes
"""

from __future__ import annotations

import json
import struct

MAX_PACKET_SIZE = 64 * 1024

# Randomly generated 16-bit frame type codes (hard-coded on both ends).
FRAME_TYPE_CTRL = 0x66F0  # 26352
FRAME_TYPE_DATA = 0x04EB  # 1259

_VALID_TYPES = (FRAME_TYPE_CTRL, FRAME_TYPE_DATA)


class ProtocolError(Exception):
    pass


def encode_frame(frame_type: int, payload: bytes) -> bytes:
    if frame_type not in _VALID_TYPES:
        raise ProtocolError(f"invalid frame type: {frame_type}")
    if len(payload) > MAX_PACKET_SIZE:
        raise ProtocolError("packet too large")
    return struct.pack(">H", frame_type) + payload


def encode_control(obj: dict) -> bytes:
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return encode_frame(FRAME_TYPE_CTRL, payload)


def decode_frame(plaintext: bytes) -> tuple[int, bytes]:
    """Split a decrypted plaintext frame into (frame_type, payload)."""
    if len(plaintext) < 2:
        raise ProtocolError("frame too short")
    (frame_type,) = struct.unpack(">H", plaintext[:2])
    if frame_type not in _VALID_TYPES:
        raise ProtocolError(f"unknown frame type: {frame_type}")
    return frame_type, plaintext[2:]


def decode_control(payload: bytes) -> dict:
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid json: {exc}") from exc
    if not isinstance(obj, dict) or "type" not in obj:
        raise ProtocolError("message missing 'type'")
    return obj
