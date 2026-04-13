from __future__ import annotations

import pytest

from qboost.keys import QBoostKeyPair, QBoostPublicKey
from qboost.utils import QBoostError


def test_generate_keypair():
    kp = QBoostKeyPair.generate()
    assert isinstance(kp, QBoostKeyPair)
    assert kp.hybrid is not None
    assert kp.created_at > 0


def test_key_id_is_hex_string():
    kp = QBoostKeyPair.generate()
    assert isinstance(kp.key_id, str)
    int(kp.key_id, 16)
    assert len(kp.key_id) == 32  # 16 bytes -> 32 hex chars


def test_export_public_key_import_roundtrip():
    kp = QBoostKeyPair.generate()
    exported = kp.export_public_key()
    assert exported.startswith(b"QBOOST-PUB-V1\n")

    imported = QBoostPublicKey.from_export(exported)
    assert imported.serialize() == kp.public_key.serialize()


def test_export_private_key_import_roundtrip_no_password():
    kp = QBoostKeyPair.generate()
    exported = kp.export_private_key()
    assert exported.startswith(b"QBOOST-SEC-V1\n")

    imported = QBoostKeyPair.from_private_key(exported)
    assert isinstance(imported, QBoostKeyPair)

    assert imported.hybrid.private_key.serialize() == kp.hybrid.private_key.serialize()


def test_export_private_key_import_roundtrip_with_password():
    kp = QBoostKeyPair.generate()
    password = "super-secret-pass"
    exported = kp.export_private_key(password=password)
    assert exported.startswith(b"QBOOST-SEC-V1\n")

    imported = QBoostKeyPair.from_private_key(exported, password=password)
    assert isinstance(imported, QBoostKeyPair)

    assert imported.hybrid.private_key.serialize() == kp.hybrid.private_key.serialize()


def test_wrong_password_raises():
    kp = QBoostKeyPair.generate()
    exported = kp.export_private_key(password="correct")
    with pytest.raises((QBoostError, Exception)):
        QBoostKeyPair.from_private_key(exported, password="wrong")


def test_encrypted_key_requires_password():
    kp = QBoostKeyPair.generate()
    exported = kp.export_private_key(password="pass")
    with pytest.raises(QBoostError, match="Password required"):
        QBoostKeyPair.from_private_key(exported, password=None)


def test_public_key_deserialize_roundtrip():
    kp = QBoostKeyPair.generate()
    pub = kp.public_key
    serialized = pub.serialize()
    restored = QBoostPublicKey.deserialize(serialized)
    assert restored.serialize() == serialized


def test_key_id_deterministic():
    kp = QBoostKeyPair.generate()
    pub = kp.public_key
    assert pub.key_id == kp.key_id
