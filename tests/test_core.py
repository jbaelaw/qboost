from __future__ import annotations

import pytest

from qboost.core import (
    decrypt,
    decrypt_symmetric,
    encrypt,
    encrypt_symmetric,
    generate_keypair,
    info,
    is_quantum_ready,
)
from qboost.keys import QBoostKeyPair, QBoostPublicKey
from qboost.utils import DecryptionError, quantum_random


def test_generate_keypair_returns_qboost_keypair():
    kp = generate_keypair()
    assert isinstance(kp, QBoostKeyPair)


def test_encrypt_decrypt_roundtrip_keypair():
    kp = generate_keypair()
    plaintext = b"quantum secure message"
    ct = encrypt(plaintext, kp.public_key)
    result = decrypt(ct, kp)
    assert result == plaintext


def test_encrypt_decrypt_roundtrip_exported_keys():
    kp = generate_keypair()
    plaintext = b"exported key round trip"

    exported_pub = kp.export_public_key()
    ct = encrypt(plaintext, exported_pub)

    exported_priv = kp.export_private_key()
    imported_kp = QBoostKeyPair.from_private_key(exported_priv)
    result = decrypt(ct, imported_kp)
    assert result == plaintext


def test_encrypt_decrypt_with_serialized_pubkey():
    kp = generate_keypair()
    plaintext = b"serialized key test"

    raw_pub = kp.public_key.serialize()
    ct = encrypt(plaintext, raw_pub)
    result = decrypt(ct, kp)
    assert result == plaintext


def test_encrypt_symmetric_decrypt_symmetric_roundtrip():
    plaintext = b"symmetric test data"
    password = "sym-pass-123"
    ct = encrypt_symmetric(plaintext, password)
    result = decrypt_symmetric(ct, password)
    assert result == plaintext


def test_is_quantum_ready_returns_bool():
    result = is_quantum_ready()
    assert isinstance(result, bool)


def test_info_returns_dict_with_expected_keys():
    result = info()
    assert isinstance(result, dict)
    expected_keys = {"version", "pq_available", "classical_kem", "pq_kem", "symmetric", "kdf"}
    assert expected_keys == set(result.keys())


def test_info_values():
    result = info()
    assert result["classical_kem"] == "X25519"
    assert result["symmetric"] == "AES-256-GCM"
    assert result["kdf"] == "Scrypt + SHAKE256"
    assert isinstance(result["version"], str)
    assert isinstance(result["pq_available"], bool)


def test_decrypt_with_wrong_key_fails():
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    plaintext = b"should not decrypt with wrong key"
    ct = encrypt(plaintext, kp1.public_key)
    with pytest.raises((DecryptionError, Exception)):
        decrypt(ct, kp2)


def test_large_data_encrypt_decrypt():
    kp = generate_keypair()
    plaintext = quantum_random(1024 * 1024)  # 1MB
    ct = encrypt(plaintext, kp.public_key)
    result = decrypt(ct, kp)
    assert result == plaintext


def test_empty_plaintext_encrypt_decrypt():
    kp = generate_keypair()
    ct = encrypt(b"", kp.public_key)
    result = decrypt(ct, kp)
    assert result == b""


def test_decrypt_invalid_header():
    kp = generate_keypair()
    with pytest.raises(DecryptionError):
        decrypt(b"INVALID" + b"\x00" * 100, kp)


def test_decrypt_too_short():
    kp = generate_keypair()
    with pytest.raises(DecryptionError):
        decrypt(b"QB", kp)
