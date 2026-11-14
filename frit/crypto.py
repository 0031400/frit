"""Self-built symmetric encryption layer.

Design (by user's request, simplest possible):

- The pre-shared key (PSK) from config is turned into a fixed AES-128 key with
  SHA-256:  aes_key = SHA256(psk)[:16].
- Every encrypted frame on every connection is AES-128-ECB + PKCS7.
- Encrypted wire format:  [2 byte big-endian ciphertext length][ciphertext]
- No handshake, no per-frame IV, no HMAC.  The "authentication middleware" is
  simply: decrypt the first frame, verify PKCS7 padding, then verify the 2-byte
  frame type is one of the two hard-coded random codes; disconnect otherwise.

NOTE: AES-ECB with a fixed key is weak against traffic analysis (identical
plaintext blocks produce identical ciphertext blocks).  It is used here only
because the user explicitly asked for the simplest workable mode.
"""

from __future__ import annotations

import hashlib
import struct

from Crypto.Cipher import AES

from .protocol import MAX_PACKET_SIZE

# Allow the frame type (2 bytes) on top of the payload budget.
MAX_PLAINTEXT_SIZE = MAX_PACKET_SIZE + 2

_LEN_SIZE = 2


class CryptoError(Exception):
    """Raised when a frame cannot be decrypted."""


def derive_key(psk: str) -> bytes:
    """Derive the fixed 16-byte AES-128 key from the pre-shared key string."""
    return hashlib.sha256(psk.encode("utf-8")).digest()[:16]


def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block != 0:
        raise CryptoError("invalid ciphertext length")
    pad = data[-1]
    if pad < 1 or pad > block:
        raise CryptoError("invalid padding")
    if data[-pad:] != bytes([pad]) * pad:
        raise CryptoError("invalid padding")
    return data[:-pad]


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-128-ECB + PKCS7."""
    if len(plaintext) > MAX_PLAINTEXT_SIZE:
        raise CryptoError("frame too large")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(_pkcs7_pad(plaintext))


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-128-ECB ciphertext and verify PKCS7 padding."""
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise CryptoError("invalid ciphertext length")
    cipher = AES.new(key, AES.MODE_ECB)
    return _pkcs7_unpad(cipher.decrypt(ciphertext))


def _read_exact(reader, n: int) -> bytes:
    buf = reader.read(n)
    if len(buf) != n:
        raise CryptoError("connection closed while reading frame")
    return buf


def read_frame(reader, key: bytes) -> bytes:
    """Read one encrypted frame from a file-like object and return plaintext."""
    length_bytes = _read_exact(reader, _LEN_SIZE)
    (length,) = struct.unpack(">H", length_bytes)
    if length <= 0 or length % 16 != 0:
        raise CryptoError(f"invalid frame length: {length}")
    ciphertext = _read_exact(reader, length)
    return decrypt(key, ciphertext)


def write_frame(writer, key: bytes, plaintext: bytes) -> None:
    """Encrypt and write one frame to a file-like object."""
    ciphertext = encrypt(key, plaintext)
    writer.write(struct.pack(">H", len(ciphertext)))
    writer.write(ciphertext)
    writer.flush()
