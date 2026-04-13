from __future__ import annotations

from qboost.hybrid import HybridKEM, HybridPrivateKey, HybridPublicKey


def test_generate_keypair():
    kp = HybridKEM.generate_keypair()
    assert kp.classical_private is not None
    assert kp.classical_public is not None
    assert kp.public_key is not None
    assert kp.private_key is not None


def test_encapsulate_decapsulate_roundtrip():
    kp = HybridKEM.generate_keypair()
    shared_secret, ct = HybridKEM.encapsulate(kp.public_key)
    recovered = HybridKEM.decapsulate(ct, kp.private_key)
    assert shared_secret == recovered


def test_shared_secret_is_32_bytes():
    kp = HybridKEM.generate_keypair()
    shared_secret, _ = HybridKEM.encapsulate(kp.public_key)
    assert len(shared_secret) == 32


def test_different_encapsulations_produce_different_ciphertexts():
    kp = HybridKEM.generate_keypair()
    _, ct1 = HybridKEM.encapsulate(kp.public_key)
    _, ct2 = HybridKEM.encapsulate(kp.public_key)
    assert ct1 != ct2


def test_public_key_serialization_roundtrip():
    kp = HybridKEM.generate_keypair()
    pub = kp.public_key
    serialized = pub.serialize()
    deserialized = HybridPublicKey.deserialize(serialized)

    assert pub.serialize() == deserialized.serialize()
    assert pub.mode == deserialized.mode


def test_private_key_serialization_roundtrip():
    kp = HybridKEM.generate_keypair()
    priv = kp.private_key
    serialized = priv.serialize()
    deserialized = HybridPrivateKey.deserialize(serialized)

    assert priv.mode == deserialized.mode

    pub = kp.public_key
    shared1, ct = HybridKEM.encapsulate(pub)
    shared2 = HybridKEM.decapsulate(ct, deserialized)
    assert shared1 == shared2


def test_decapsulation_with_wrong_key_produces_different_secret():
    kp1 = HybridKEM.generate_keypair()
    kp2 = HybridKEM.generate_keypair()

    shared_secret, ct = HybridKEM.encapsulate(kp1.public_key)
    try:
        recovered = HybridKEM.decapsulate(ct, kp2.private_key)
        assert recovered != shared_secret
    except Exception:
        pass


def test_multiple_keypairs_are_different():
    kp1 = HybridKEM.generate_keypair()
    kp2 = HybridKEM.generate_keypair()
    assert kp1.public_key.serialize() != kp2.public_key.serialize()
