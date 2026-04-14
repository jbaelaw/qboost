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
from qboost.utils import DecryptionError, QBoostError, quantum_random


def test_keygen():
    kp = generate_keypair()
    assert isinstance(kp, QBoostKeyPair)


def test_roundtrip():
    kp = generate_keypair()
    plaintext = b"quantum secure message"
    ct = encrypt(plaintext, kp.public_key)
    result = decrypt(ct, kp)
    assert result == plaintext


def test_roundtrip_exported():
    kp = generate_keypair()
    plaintext = b"exported key round trip"

    exported_pub = kp.export_public_key()
    ct = encrypt(plaintext, exported_pub)

    exported_priv = kp.export_private_key()
    imported_kp = QBoostKeyPair.from_private_key(exported_priv)
    result = decrypt(ct, imported_kp)
    assert result == plaintext


def test_roundtrip_serialized():
    kp = generate_keypair()
    plaintext = b"serialized key test"

    raw_pub = kp.public_key.serialize()
    ct = encrypt(plaintext, raw_pub)
    result = decrypt(ct, kp)
    assert result == plaintext


def test_symmetric():
    plaintext = b"symmetric test data"
    password = "sym-pass-123"
    ct = encrypt_symmetric(plaintext, password)
    result = decrypt_symmetric(ct, password)
    assert result == plaintext


def test_pq_ready():
    from qboost.utils import PQ_AVAILABLE
    assert is_quantum_ready() == PQ_AVAILABLE


def test_info():
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


def test_wrong_key():
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    plaintext = b"should not decrypt with wrong key"
    ct = encrypt(plaintext, kp1.public_key)
    with pytest.raises(DecryptionError):
        decrypt(ct, kp2)


def test_large():
    kp = generate_keypair()
    plaintext = quantum_random(1024 * 1024)  # 1MB
    ct = encrypt(plaintext, kp.public_key)
    result = decrypt(ct, kp)
    assert result == plaintext


def test_empty():
    kp = generate_keypair()
    ct = encrypt(b"", kp.public_key)
    result = decrypt(ct, kp)
    assert result == b""


def test_bad_header():
    kp = generate_keypair()
    with pytest.raises(DecryptionError):
        decrypt(b"INVALID" + b"\x00" * 100, kp)


def test_short_ct():
    kp = generate_keypair()
    with pytest.raises(DecryptionError):
        decrypt(b"QB", kp)


def test_encrypt_type_error():
    kp = generate_keypair()
    with pytest.raises(TypeError):
        encrypt("not bytes", kp.public_key)


def test_decrypt_type_error():
    kp = generate_keypair()
    with pytest.raises(TypeError):
        decrypt("not bytes", kp)


def test_symmetric_type_error():
    with pytest.raises(TypeError):
        encrypt_symmetric("not bytes", "pw")
    with pytest.raises(TypeError):
        decrypt_symmetric("not bytes", "pw")


def test_decrypt_with_hybrid_priv():
    kp = generate_keypair()
    ct = encrypt(b"hybrid priv test", kp.public_key)
    from qboost.hybrid import HybridKEM
    pt = decrypt(ct, kp.hybrid.private_key)
    assert pt == b"hybrid priv test"


def test_qboosterror_wrapped():
    """Corrupt KEM payload should raise DecryptionError, not QBoostError."""
    kp = generate_keypair()
    magic = b"QB1"
    fake_kem = bytes([0xFF]) + b'\x00' * 32 + b'\x00' * 50
    fake_ct = magic + len(fake_kem).to_bytes(2, 'big') + fake_kem + b'\x00' * 60
    with pytest.raises(DecryptionError):
        decrypt(fake_ct, kp)
