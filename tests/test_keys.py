from __future__ import annotations

import pytest

from qboost.keys import QBoostKeyPair, QBoostPublicKey
from qboost.utils import DecryptionError, QBoostError


def test_keygen():
    kp = QBoostKeyPair.generate()
    assert isinstance(kp, QBoostKeyPair)
    assert kp.hybrid is not None
    assert kp.created_at > 0


def test_key_id():
    kp = QBoostKeyPair.generate()
    assert isinstance(kp.key_id, str)
    int(kp.key_id, 16)
    assert len(kp.key_id) == 32  # 16 bytes -> 32 hex chars


def test_pub_export():
    kp = QBoostKeyPair.generate()
    exported = kp.export_public_key()
    assert exported.startswith(b"QBOOST-PUB-V1\n")

    imported = QBoostPublicKey.from_export(exported)
    assert imported.serialize() == kp.public_key.serialize()


def test_priv_export():
    kp = QBoostKeyPair.generate()
    exported = kp.export_private_key()
    assert exported.startswith(b"QBOOST-SEC-V1\n")

    imported = QBoostKeyPair.from_private_key(exported)
    assert isinstance(imported, QBoostKeyPair)

    assert imported.hybrid.private_key.serialize() == kp.hybrid.private_key.serialize()


def test_priv_export_encrypted():
    kp = QBoostKeyPair.generate()
    password = "super-secret-pass"
    exported = kp.export_private_key(password=password)
    assert exported.startswith(b"QBOOST-SEC-V1\n")

    imported = QBoostKeyPair.from_private_key(exported, password=password)
    assert isinstance(imported, QBoostKeyPair)

    assert imported.hybrid.private_key.serialize() == kp.hybrid.private_key.serialize()


def test_wrong_pw():
    kp = QBoostKeyPair.generate()
    exported = kp.export_private_key(password="correct")
    with pytest.raises(DecryptionError):
        QBoostKeyPair.from_private_key(exported, password="wrong")


def test_missing_pw():
    kp = QBoostKeyPair.generate()
    exported = kp.export_private_key(password="pass")
    with pytest.raises(QBoostError, match="Password required"):
        QBoostKeyPair.from_private_key(exported, password=None)


def test_pub_serde():
    kp = QBoostKeyPair.generate()
    pub = kp.public_key
    serialized = pub.serialize()
    restored = QBoostPublicKey.deserialize(serialized)
    assert restored.serialize() == serialized


def test_key_id_stable():
    kp = QBoostKeyPair.generate()
    pub = kp.public_key
    assert pub.key_id == kp.key_id


def test_repr():
    kp = QBoostKeyPair.generate()
    r = repr(kp)
    assert "QBoostKeyPair" in r
    assert kp.key_id in r

    pr = repr(kp.public_key)
    assert "QBoostPublicKey" in pr


def test_export_import_encrypt_roundtrip():
    """Exported and reimported keypair must be able to decrypt."""
    kp = QBoostKeyPair.generate()
    msg = b"roundtrip after export"

    from qboost.core import encrypt, decrypt
    ct = encrypt(msg, kp.public_key)

    exported = kp.export_private_key("test-pw")
    imported = QBoostKeyPair.from_private_key(exported, "test-pw")

    pt = decrypt(ct, imported)
    assert pt == msg

    ct2 = encrypt(msg, imported.public_key)
    pt2 = decrypt(ct2, kp)
    assert pt2 == msg
