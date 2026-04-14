from __future__ import annotations

import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .symmetric import decrypt_with_key, encrypt_with_key
from .utils import MODE_CLASSICAL, MODE_HYBRID, PQ_AVAILABLE, QBoostError, quantum_random

try:
    import oqs

    _PQ_KEM_ALG: str | None = None
    for candidate in ("ML-KEM-768", "Kyber768"):
        if candidate in oqs.get_enabled_KEM_mechanisms():
            _PQ_KEM_ALG = candidate
            break
    if _PQ_KEM_ALG is None:
        oqs = None  # type: ignore[assignment]
except ImportError:
    oqs = None  # type: ignore[assignment]
    _PQ_KEM_ALG = None

_HKDF_INFO = b"qboost-hybrid-kem-v1"
_HKDF_ENTROPY_INFO = b"qboost-entropy-wrap-v1"
_X25519_PUB_LEN = 32
_X25519_PRIV_LEN = 32


def _hkdf_derive(ikm: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=length,
        salt=None,
        info=_HKDF_INFO,
    ).derive(ikm)


def _hkdf_entropy_key(ikm: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=length,
        salt=None,
        info=_HKDF_ENTROPY_INFO,
    ).derive(ikm)


class HybridPublicKey:
    def __init__(
        self,
        classical_public: X25519PublicKey,
        pq_public: bytes | None = None,
    ):
        self.classical_public = classical_public
        self.pq_public = pq_public

    @property
    def mode(self) -> int:
        return MODE_HYBRID if self.pq_public is not None else MODE_CLASSICAL

    def serialize(self) -> bytes:
        x_pub = self.classical_public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        if self.pq_public is not None:
            return bytes([MODE_HYBRID]) + x_pub + self.pq_public
        return bytes([MODE_CLASSICAL]) + x_pub

    def __repr__(self) -> str:
        mode = "hybrid" if self.pq_public is not None else "classical"
        return f"HybridPublicKey(mode={mode})"

    @classmethod
    def deserialize(cls, data: bytes) -> HybridPublicKey:
        if len(data) < 1 + _X25519_PUB_LEN:
            raise QBoostError("Public key data too short")

        mode = data[0]
        x_pub = X25519PublicKey.from_public_bytes(data[1 : 1 + _X25519_PUB_LEN])

        if mode == MODE_HYBRID:
            pq_pub = data[1 + _X25519_PUB_LEN :]
            if not pq_pub:
                raise QBoostError("Missing PQ public key in hybrid mode")
            return cls(x_pub, pq_pub)
        elif mode == MODE_CLASSICAL:
            return cls(x_pub)
        else:
            raise QBoostError(f"Unknown key mode: 0x{mode:02x}")


class HybridPrivateKey:
    def __init__(
        self,
        classical_private: X25519PrivateKey,
        pq_private: bytes | None = None,
    ):
        self.classical_private = classical_private
        self.pq_private = pq_private

    @property
    def mode(self) -> int:
        return MODE_HYBRID if self.pq_private is not None else MODE_CLASSICAL

    def __repr__(self) -> str:
        mode = "hybrid" if self.pq_private is not None else "classical"
        return f"HybridPrivateKey(mode={mode})"

    def serialize(self) -> bytes:
        x_priv = self.classical_private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        if self.pq_private is not None:
            pq_len = struct.pack(">H", len(self.pq_private))
            return bytes([MODE_HYBRID]) + x_priv + pq_len + self.pq_private
        return bytes([MODE_CLASSICAL]) + x_priv

    @classmethod
    def deserialize(cls, data: bytes) -> HybridPrivateKey:
        if len(data) < 1 + _X25519_PRIV_LEN:
            raise QBoostError("Private key data too short")

        mode = data[0]
        x_priv = X25519PrivateKey.from_private_bytes(data[1 : 1 + _X25519_PRIV_LEN])

        if mode == MODE_HYBRID:
            rest = data[1 + _X25519_PRIV_LEN :]
            if len(rest) < 2:
                raise QBoostError("Missing PQ private key length")
            pq_len = struct.unpack(">H", rest[:2])[0]
            pq_priv = rest[2 : 2 + pq_len]
            if len(pq_priv) != pq_len:
                raise QBoostError("Truncated PQ private key")
            return cls(x_priv, pq_priv)
        elif mode == MODE_CLASSICAL:
            return cls(x_priv)
        else:
            raise QBoostError(f"Unknown key mode: 0x{mode:02x}")


class HybridKeyPair:
    def __init__(
        self,
        classical_private: X25519PrivateKey,
        classical_public: X25519PublicKey,
        pq_private: bytes | None = None,
        pq_public: bytes | None = None,
    ):
        self.classical_private = classical_private
        self.classical_public = classical_public
        self.pq_private = pq_private
        self.pq_public = pq_public

    @property
    def public_key(self) -> HybridPublicKey:
        return HybridPublicKey(self.classical_public, self.pq_public)

    @property
    def private_key(self) -> HybridPrivateKey:
        return HybridPrivateKey(self.classical_private, self.pq_private)


class HybridKEM:
    @staticmethod
    def generate_keypair() -> HybridKeyPair:
        x_priv = X25519PrivateKey.generate()
        x_pub = x_priv.public_key()

        pq_priv: bytes | None = None
        pq_pub: bytes | None = None

        if PQ_AVAILABLE and oqs is not None and _PQ_KEM_ALG is not None:
            kem = oqs.KeyEncapsulation(_PQ_KEM_ALG)
            pq_pub = kem.generate_keypair()
            pq_priv = kem.export_secret_key()

        return HybridKeyPair(x_priv, x_pub, pq_priv, pq_pub)

    @staticmethod
    def encapsulate(public_key: HybridPublicKey) -> tuple[bytes, bytes]:
        ephemeral_priv = X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()
        classical_secret = ephemeral_priv.exchange(public_key.classical_public)

        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        if public_key.pq_public is not None and (oqs is None or _PQ_KEM_ALG is None):
            raise QBoostError("Hybrid public key requires oqs library for encapsulation")

        if (
            public_key.pq_public is not None
            and oqs is not None
            and _PQ_KEM_ALG is not None
        ):
            kem = oqs.KeyEncapsulation(_PQ_KEM_ALG)
            pq_ct, pq_secret = kem.encap_secret(public_key.pq_public)

            shared_secret = _hkdf_derive(classical_secret + pq_secret)
            ct = bytes([MODE_HYBRID]) + ephemeral_pub_bytes + pq_ct
        else:
            extra_entropy = quantum_random(32)
            classical_key = _hkdf_entropy_key(classical_secret)
            encrypted_entropy = encrypt_with_key(extra_entropy, classical_key)

            shared_secret = _hkdf_derive(classical_secret + extra_entropy)
            ct = bytes([MODE_CLASSICAL]) + ephemeral_pub_bytes + encrypted_entropy

        return shared_secret, ct

    @staticmethod
    def decapsulate(ciphertext: bytes, private_key: HybridPrivateKey) -> bytes:
        if len(ciphertext) < 1 + _X25519_PUB_LEN:
            raise QBoostError("KEM ciphertext too short")

        mode = ciphertext[0]
        ephemeral_pub = X25519PublicKey.from_public_bytes(
            ciphertext[1 : 1 + _X25519_PUB_LEN]
        )
        rest = ciphertext[1 + _X25519_PUB_LEN :]

        classical_secret = private_key.classical_private.exchange(ephemeral_pub)

        if mode == MODE_HYBRID:
            if private_key.pq_private is None or oqs is None or _PQ_KEM_ALG is None:
                raise QBoostError(
                    "Hybrid ciphertext requires PQ private key and oqs library"
                )
            kem = oqs.KeyEncapsulation(_PQ_KEM_ALG, secret_key=private_key.pq_private)
            pq_secret = kem.decap_secret(rest)
            return _hkdf_derive(classical_secret + pq_secret)

        elif mode == MODE_CLASSICAL:
            classical_key = _hkdf_entropy_key(classical_secret)
            extra_entropy = decrypt_with_key(rest, classical_key)
            return _hkdf_derive(classical_secret + extra_entropy)

        else:
            raise QBoostError(f"Unknown KEM mode: 0x{mode:02x}")
