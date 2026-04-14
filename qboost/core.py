from __future__ import annotations

from .hybrid import HybridKEM, HybridPrivateKey
from .keys import QBoostKeyPair, QBoostPublicKey
from .symmetric import decrypt_with_key, encrypt_with_key
from .symmetric import decrypt as _sym_decrypt
from .symmetric import encrypt as _sym_encrypt
from .utils import PQ_AVAILABLE, VERSION, DecryptionError, QBoostError

_MAGIC = b"QB1"


def generate_keypair() -> QBoostKeyPair:
    return QBoostKeyPair.generate()


def encrypt(
    plaintext: bytes,
    recipient_public_key: QBoostPublicKey | bytes,
) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if isinstance(recipient_public_key, bytes):
        if recipient_public_key.startswith(b"QBOOST-PUB-V1\n"):
            pub = QBoostPublicKey.from_export(recipient_public_key)
        else:
            pub = QBoostPublicKey.deserialize(recipient_public_key)
    else:
        pub = recipient_public_key

    shared_secret, kem_ct = HybridKEM.encapsulate(pub.hybrid_public)
    if len(kem_ct) > 0xFFFF:
        raise QBoostError("KEM ciphertext exceeds maximum frame size")
    encrypted = encrypt_with_key(plaintext, shared_secret)

    kem_ct_len = len(kem_ct).to_bytes(2, "big")
    return _MAGIC + kem_ct_len + kem_ct + encrypted


def decrypt(
    ciphertext: bytes,
    private_key: QBoostKeyPair | HybridPrivateKey,
) -> bytes:
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    if len(ciphertext) < len(_MAGIC) + 2:
        raise DecryptionError("Ciphertext too short")

    if ciphertext[: len(_MAGIC)] != _MAGIC:
        raise DecryptionError("Invalid qboost ciphertext header")

    offset = len(_MAGIC)
    kem_ct_len = int.from_bytes(ciphertext[offset : offset + 2], "big")
    offset += 2

    if len(ciphertext) < offset + kem_ct_len:
        raise DecryptionError("Truncated KEM ciphertext")

    kem_ct = ciphertext[offset : offset + kem_ct_len]
    encrypted = ciphertext[offset + kem_ct_len :]

    if isinstance(private_key, QBoostKeyPair):
        hybrid_priv = private_key.hybrid.private_key
    else:
        hybrid_priv = private_key

    try:
        shared_secret = HybridKEM.decapsulate(kem_ct, hybrid_priv)
        return decrypt_with_key(encrypted, shared_secret)
    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError("Decryption failed") from e


def encrypt_symmetric(plaintext: bytes, password: str) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    return _sym_encrypt(plaintext, password)


def decrypt_symmetric(ciphertext: bytes, password: str) -> bytes:
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    return _sym_decrypt(ciphertext, password)


def is_quantum_ready() -> bool:
    return PQ_AVAILABLE


def info() -> dict:
    return {
        "version": VERSION,
        "pq_available": PQ_AVAILABLE,
        "classical_kem": "X25519",
        "pq_kem": "ML-KEM-768" if PQ_AVAILABLE else "N/A (hash-enhanced)",
        "symmetric": "AES-256-GCM",
        "kdf": "Scrypt + SHAKE256",
    }
