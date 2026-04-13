from __future__ import annotations

from qboost.utils import (
    VERSION,
    quantum_random,
    sha3_256,
    shake256,
)


def test_random_length():
    for n in (0, 1, 16, 32, 64, 256):
        result = quantum_random(n)
        assert isinstance(result, bytes)
        assert len(result) == n


def test_random_unique():
    a = quantum_random(32)
    b = quantum_random(32)
    assert a != b


def test_shake256():
    data = b"hello world"
    h1 = shake256(data)
    h2 = shake256(data)
    assert h1 == h2
    assert len(h1) == 32


def test_shake256_length():
    data = b"test"
    h = shake256(data, length=64)
    assert len(h) == 64


def test_shake256_differ():
    assert shake256(b"a") != shake256(b"b")


def test_sha3_256():
    data = b"hello world"
    h1 = sha3_256(data)
    h2 = sha3_256(data)
    assert h1 == h2
    assert len(h1) == 32


def test_sha3_256_differ():
    assert sha3_256(b"a") != sha3_256(b"b")


def test_version():
    assert isinstance(VERSION, str)
    assert len(VERSION) > 0
