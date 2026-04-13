from __future__ import annotations

import hashlib
import hmac
import os

VERSION = "0.1.0"

try:
    import oqs  # noqa: F401
    PQ_AVAILABLE = True
except ImportError:
    PQ_AVAILABLE = False


def check_pq() -> bool:
    return PQ_AVAILABLE


def quantum_random(n: int) -> bytes:
    return os.urandom(n)


def shake256(data: bytes, length: int = 32) -> bytes:
    h = hashlib.shake_256(data)
    return h.digest(length)


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def combine_secrets(*secrets: bytes) -> bytes:
    combined = b"qboost-combine-v1" + b"".join(secrets)
    return shake256(combined, 32)


class QBoostError(Exception):
    pass


class DecryptionError(QBoostError):
    pass
