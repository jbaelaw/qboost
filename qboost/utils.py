from __future__ import annotations

import hashlib
import os

VERSION = "0.8.5"

try:
    import oqs  # noqa: F401
    PQ_AVAILABLE = True
except ImportError:
    PQ_AVAILABLE = False

MODE_CLASSICAL: int = 0x01
MODE_HYBRID: int = 0x02


def quantum_random(n: int) -> bytes:
    return os.urandom(n)


def shake256(data: bytes, length: int = 32) -> bytes:
    h = hashlib.shake_256(data)
    return h.digest(length)


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


class QBoostError(Exception):
    pass


class DecryptionError(QBoostError):
    pass
