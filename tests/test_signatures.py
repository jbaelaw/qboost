from __future__ import annotations

from qboost.signatures import HybridSigner, SigningKeyPair, SigningPrivateKey, SigningPublicKey


def test_keygen():
    kp = HybridSigner.generate_keypair()
    assert isinstance(kp, SigningKeyPair)
    assert kp.classical_private is not None
    assert kp.classical_public is not None
    assert isinstance(kp.public_key, SigningPublicKey)
    assert isinstance(kp.private_key, SigningPrivateKey)


def test_roundtrip():
    kp = HybridSigner.generate_keypair()
    message = b"sign this message"
    sig = HybridSigner.sign(message, kp.private_key)
    assert HybridSigner.verify(message, sig, kp.public_key) is True


def test_wrong_msg():
    kp = HybridSigner.generate_keypair()
    sig = HybridSigner.sign(b"original", kp.private_key)
    assert HybridSigner.verify(b"tampered", sig, kp.public_key) is False


def test_wrong_key():
    kp1 = HybridSigner.generate_keypair()
    kp2 = HybridSigner.generate_keypair()
    message = b"check key mismatch"
    sig = HybridSigner.sign(message, kp1.private_key)
    assert HybridSigner.verify(message, sig, kp2.public_key) is False


def test_deterministic():
    kp = HybridSigner.generate_keypair()
    message = b"deterministic signature test"
    sig1 = HybridSigner.sign(message, kp.private_key)
    sig2 = HybridSigner.sign(message, kp.private_key)
    assert sig1 == sig2


def test_pub_serde():
    kp = HybridSigner.generate_keypair()
    pub = kp.public_key
    serialized = pub.serialize()
    restored = SigningPublicKey.deserialize(serialized)

    assert pub.serialize() == restored.serialize()
    assert pub.mode == restored.mode

    message = b"serialization test"
    sig = HybridSigner.sign(message, kp.private_key)
    assert HybridSigner.verify(message, sig, restored) is True


def test_priv_serde():
    kp = HybridSigner.generate_keypair()
    priv = kp.private_key
    serialized = priv.serialize()
    restored = SigningPrivateKey.deserialize(serialized)

    assert priv.mode == restored.mode

    message = b"private key round trip"
    sig = HybridSigner.sign(message, restored)
    assert HybridSigner.verify(message, sig, kp.public_key) is True


def test_empty():
    kp = HybridSigner.generate_keypair()
    sig = HybridSigner.sign(b"", kp.private_key)
    assert HybridSigner.verify(b"", sig, kp.public_key) is True


def test_large():
    kp = HybridSigner.generate_keypair()
    message = b"A" * (1024 * 1024)  # 1MB
    sig = HybridSigner.sign(message, kp.private_key)
    assert HybridSigner.verify(message, sig, kp.public_key) is True


def test_mode_byte():
    kp = HybridSigner.generate_keypair()
    sig = HybridSigner.sign(b"test", kp.private_key)
    assert sig[0] == 0x01 or sig[0] == 0x02


def test_truncated():
    kp = HybridSigner.generate_keypair()
    assert HybridSigner.verify(b"msg", b"\x01", kp.public_key) is False


def test_different_sigs():
    kp = HybridSigner.generate_keypair()
    sig1 = HybridSigner.sign(b"message1", kp.private_key)
    sig2 = HybridSigner.sign(b"message2", kp.private_key)
    assert sig1 != sig2
