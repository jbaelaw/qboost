from __future__ import annotations

from qboost.utils import (
    VERSION,
    combine_secrets,
    constant_time_compare,
    quantum_random,
    sha3_256,
    shake256,
)


def test_quantum_random_returns_correct_length():
    for n in (0, 1, 16, 32, 64, 256):
        result = quantum_random(n)
        assert isinstance(result, bytes)
        assert len(result) == n


def test_quantum_random_different_each_call():
    a = quantum_random(32)
    b = quantum_random(32)
    assert a != b


def test_shake256_consistent_output():
    data = b"hello world"
    h1 = shake256(data)
    h2 = shake256(data)
    assert h1 == h2
    assert len(h1) == 32


def test_shake256_custom_length():
    data = b"test"
    h = shake256(data, length=64)
    assert len(h) == 64


def test_shake256_different_inputs_differ():
    assert shake256(b"a") != shake256(b"b")


def test_sha3_256_consistent_output():
    data = b"hello world"
    h1 = sha3_256(data)
    h2 = sha3_256(data)
    assert h1 == h2
    assert len(h1) == 32


def test_sha3_256_different_inputs_differ():
    assert sha3_256(b"a") != sha3_256(b"b")


def test_constant_time_compare_equal():
    assert constant_time_compare(b"abc", b"abc") is True


def test_constant_time_compare_not_equal():
    assert constant_time_compare(b"abc", b"abd") is False


def test_constant_time_compare_different_length():
    assert constant_time_compare(b"abc", b"abcd") is False


def test_constant_time_compare_empty():
    assert constant_time_compare(b"", b"") is True


def test_combine_secrets_deterministic():
    a = b"secret1"
    b_ = b"secret2"
    r1 = combine_secrets(a, b_)
    r2 = combine_secrets(a, b_)
    assert r1 == r2
    assert len(r1) == 32


def test_combine_secrets_order_matters():
    a = b"secret1"
    b_ = b"secret2"
    assert combine_secrets(a, b_) != combine_secrets(b_, a)


def test_combine_secrets_different_inputs():
    assert combine_secrets(b"a") != combine_secrets(b"b")


def test_version_is_string():
    assert isinstance(VERSION, str)
    assert len(VERSION) > 0
