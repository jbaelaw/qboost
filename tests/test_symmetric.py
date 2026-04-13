from __future__ import annotations

import pytest

from qboost.symmetric import decrypt, decrypt_with_key, derive_key, encrypt, encrypt_with_key
from qboost.utils import DecryptionError, quantum_random


def test_derive_key_returns_key_and_salt():
    key, salt = derive_key("password")
    assert isinstance(key, bytes)
    assert isinstance(salt, bytes)
    assert len(key) == 32
    assert len(salt) == 32


def test_derive_key_deterministic_with_same_salt():
    key1, salt = derive_key("password")
    key2, _ = derive_key("password", salt=salt)
    assert key1 == key2


def test_derive_key_different_passwords():
    key1, salt = derive_key("password1")
    key2, _ = derive_key("password2", salt=salt)
    assert key1 != key2


def test_derive_key_custom_length():
    key, _ = derive_key("password", key_length=64)
    assert len(key) == 64


def test_encrypt_decrypt_roundtrip_password():
    plaintext = b"hello quantum world"
    password = "strong-password-123"
    ct = encrypt(plaintext, password)
    result = decrypt(ct, password)
    assert result == plaintext


def test_encrypt_with_key_decrypt_with_key_roundtrip():
    key = quantum_random(32)
    plaintext = b"key-based encryption test"
    ct = encrypt_with_key(plaintext, key)
    result = decrypt_with_key(ct, key)
    assert result == plaintext


def test_decrypt_wrong_password_raises():
    plaintext = b"secret data"
    ct = encrypt(plaintext, "correct-password")
    with pytest.raises(DecryptionError):
        decrypt(ct, "wrong-password")


def test_decrypt_with_wrong_key_raises():
    key = quantum_random(32)
    wrong_key = quantum_random(32)
    plaintext = b"secret data"
    ct = encrypt_with_key(plaintext, key)
    with pytest.raises(DecryptionError):
        decrypt_with_key(ct, wrong_key)


def test_empty_plaintext_roundtrip():
    password = "password"
    ct = encrypt(b"", password)
    result = decrypt(ct, password)
    assert result == b""


def test_empty_plaintext_with_key_roundtrip():
    key = quantum_random(32)
    ct = encrypt_with_key(b"", key)
    result = decrypt_with_key(ct, key)
    assert result == b""


def test_large_data_encrypt_decrypt():
    plaintext = quantum_random(1024 * 1024)  # 1MB
    password = "large-data-password"
    ct = encrypt(plaintext, password)
    result = decrypt(ct, password)
    assert result == plaintext


def test_large_data_with_key():
    key = quantum_random(32)
    plaintext = quantum_random(1024 * 1024)
    ct = encrypt_with_key(plaintext, key)
    result = decrypt_with_key(ct, key)
    assert result == plaintext


def test_ciphertext_tampering_detected():
    password = "password"
    ct = bytearray(encrypt(b"sensitive", password))
    ct[-1] ^= 0xFF
    with pytest.raises(DecryptionError):
        decrypt(bytes(ct), password)


def test_ciphertext_tampering_with_key():
    key = quantum_random(32)
    ct = bytearray(encrypt_with_key(b"sensitive", key))
    ct[-1] ^= 0xFF
    with pytest.raises(DecryptionError):
        decrypt_with_key(bytes(ct), key)


def test_encrypt_with_key_wrong_key_length():
    with pytest.raises(ValueError):
        encrypt_with_key(b"data", b"short")


def test_decrypt_with_key_wrong_key_length():
    with pytest.raises(ValueError):
        decrypt_with_key(b"data" * 10, b"short")


def test_decrypt_ciphertext_too_short():
    with pytest.raises(DecryptionError):
        decrypt(b"short", "password")
