from __future__ import annotations

from qboost.signatures import HybridSigner, SigningKeyPair, SigningPrivateKey, SigningPublicKey


def test_generate_keypair_produces_valid_keypair():
    kp = HybridSigner.generate_keypair()
    assert isinstance(kp, SigningKeyPair)
    assert kp.classical_private is not None
    assert kp.classical_public is not None
    assert isinstance(kp.public_key, SigningPublicKey)
    assert isinstance(kp.private_key, SigningPrivateKey)


def test_sign_verify_roundtrip():
    kp = HybridSigner.generate_keypair()
    message = b"sign this message"
    sig = HybridSigner.sign(message, kp.private_key)
    assert HybridSigner.verify(message, sig, kp.public_key) is True


def test_verify_wrong_message_fails():
    kp = HybridSigner.generate_keypair()
    sig = HybridSigner.sign(b"original", kp.private_key)
    assert HybridSigner.verify(b"tampered", sig, kp.public_key) is False


def test_verify_wrong_public_key_fails():
    kp1 = HybridSigner.generate_keypair()
    kp2 = HybridSigner.generate_keypair()
    message = b"check key mismatch"
    sig = HybridSigner.sign(message, kp1.private_key)
    assert HybridSigner.verify(message, sig, kp2.public_key) is False


def test_signature_deterministic_for_ed25519():
    kp = HybridSigner.generate_keypair()
    message = b"deterministic signature test"
    sig1 = HybridSigner.sign(message, kp.private_key)
    sig2 = HybridSigner.sign(message, kp.private_key)
    assert sig1 == sig2


def test_public_key_serialize_deserialize_roundtrip():
    kp = HybridSigner.generate_keypair()
    pub = kp.public_key
    serialized = pub.serialize()
    restored = SigningPublicKey.deserialize(serialized)

    assert pub.serialize() == restored.serialize()
    assert pub.mode == restored.mode

    message = b"serialization test"
    sig = HybridSigner.sign(message, kp.private_key)
    assert HybridSigner.verify(message, sig, restored) is True


def test_private_key_serialize_deserialize_roundtrip():
    kp = HybridSigner.generate_keypair()
    priv = kp.private_key
    serialized = priv.serialize()
    restored = SigningPrivateKey.deserialize(serialized)

    assert priv.mode == restored.mode

    message = b"private key round trip"
    sig = HybridSigner.sign(message, restored)
    assert HybridSigner.verify(message, sig, kp.public_key) is True


def test_empty_message_sign_verify():
    kp = HybridSigner.generate_keypair()
    sig = HybridSigner.sign(b"", kp.private_key)
    assert HybridSigner.verify(b"", sig, kp.public_key) is True


def test_large_message_sign_verify():
    kp = HybridSigner.generate_keypair()
    message = b"A" * (1024 * 1024)  # 1MB
    sig = HybridSigner.sign(message, kp.private_key)
    assert HybridSigner.verify(message, sig, kp.public_key) is True


def test_signature_mode_byte_classical():
    kp = HybridSigner.generate_keypair()
    sig = HybridSigner.sign(b"test", kp.private_key)
    assert sig[0] == 0x01 or sig[0] == 0x02


def test_verify_truncated_signature_fails():
    kp = HybridSigner.generate_keypair()
    assert HybridSigner.verify(b"msg", b"\x01", kp.public_key) is False


def test_different_messages_produce_different_signatures():
    kp = HybridSigner.generate_keypair()
    sig1 = HybridSigner.sign(b"message1", kp.private_key)
    sig2 = HybridSigner.sign(b"message2", kp.private_key)
    assert sig1 != sig2
