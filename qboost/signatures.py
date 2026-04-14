from __future__ import annotations

import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .utils import MODE_CLASSICAL, MODE_HYBRID, QBoostError

try:
    import oqs

    _PQ_SIG_ALG: str | None = None
    for candidate in ("ML-DSA-65", "Dilithium3"):
        if candidate in oqs.get_enabled_sig_mechanisms():
            _PQ_SIG_ALG = candidate
            break
    if _PQ_SIG_ALG is None:
        oqs = None  # type: ignore[assignment]
except ImportError:
    oqs = None  # type: ignore[assignment]
    _PQ_SIG_ALG = None

_ED25519_PUB_LEN = 32
_ED25519_PRIV_LEN = 32
_ED25519_SIG_LEN = 64


class SigningPublicKey:
    def __init__(
        self,
        classical_public: Ed25519PublicKey,
        pq_public: bytes | None = None,
    ):
        self.classical_public = classical_public
        self.pq_public = pq_public

    @property
    def mode(self) -> int:
        return MODE_HYBRID if self.pq_public is not None else MODE_CLASSICAL

    def __repr__(self) -> str:
        mode = "hybrid" if self.pq_public is not None else "classical"
        return f"SigningPublicKey(mode={mode})"

    def serialize(self) -> bytes:
        ed_pub = self.classical_public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        if self.pq_public is not None:
            return bytes([MODE_HYBRID]) + ed_pub + self.pq_public
        return bytes([MODE_CLASSICAL]) + ed_pub

    @classmethod
    def deserialize(cls, data: bytes) -> SigningPublicKey:
        if len(data) < 1 + _ED25519_PUB_LEN:
            raise QBoostError("Signing public key data too short")

        mode = data[0]
        ed_pub = Ed25519PublicKey.from_public_bytes(data[1 : 1 + _ED25519_PUB_LEN])

        if mode == MODE_HYBRID:
            pq_pub = data[1 + _ED25519_PUB_LEN :]
            if not pq_pub:
                raise QBoostError("Missing PQ public key in hybrid mode")
            return cls(ed_pub, pq_pub)
        elif mode == MODE_CLASSICAL:
            return cls(ed_pub)
        else:
            raise QBoostError(f"Unknown signing key mode: 0x{mode:02x}")


class SigningPrivateKey:
    def __init__(
        self,
        classical_private: Ed25519PrivateKey,
        pq_private: bytes | None = None,
    ):
        self.classical_private = classical_private
        self.pq_private = pq_private

    @property
    def mode(self) -> int:
        return MODE_HYBRID if self.pq_private is not None else MODE_CLASSICAL

    def serialize(self) -> bytes:
        ed_priv = self.classical_private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        if self.pq_private is not None:
            pq_len = struct.pack(">H", len(self.pq_private))
            return bytes([MODE_HYBRID]) + ed_priv + pq_len + self.pq_private
        return bytes([MODE_CLASSICAL]) + ed_priv

    @classmethod
    def deserialize(cls, data: bytes) -> SigningPrivateKey:
        if len(data) < 1 + _ED25519_PRIV_LEN:
            raise QBoostError("Signing private key data too short")

        mode = data[0]
        ed_priv = Ed25519PrivateKey.from_private_bytes(
            data[1 : 1 + _ED25519_PRIV_LEN]
        )

        if mode == MODE_HYBRID:
            rest = data[1 + _ED25519_PRIV_LEN :]
            if len(rest) < 2:
                raise QBoostError("Missing PQ private key length")
            pq_len = struct.unpack(">H", rest[:2])[0]
            pq_priv = rest[2 : 2 + pq_len]
            if len(pq_priv) != pq_len:
                raise QBoostError("Truncated PQ signing private key")
            return cls(ed_priv, pq_priv)
        elif mode == MODE_CLASSICAL:
            return cls(ed_priv)
        else:
            raise QBoostError(f"Unknown signing key mode: 0x{mode:02x}")


class SigningKeyPair:
    def __init__(
        self,
        classical_private: Ed25519PrivateKey,
        classical_public: Ed25519PublicKey,
        pq_private: bytes | None = None,
        pq_public: bytes | None = None,
    ):
        self.classical_private = classical_private
        self.classical_public = classical_public
        self.pq_private = pq_private
        self.pq_public = pq_public

    @property
    def public_key(self) -> SigningPublicKey:
        return SigningPublicKey(self.classical_public, self.pq_public)

    @property
    def private_key(self) -> SigningPrivateKey:
        return SigningPrivateKey(self.classical_private, self.pq_private)


class HybridSigner:

    @staticmethod
    def generate_keypair() -> SigningKeyPair:
        ed_priv = Ed25519PrivateKey.generate()
        ed_pub = ed_priv.public_key()

        pq_priv: bytes | None = None
        pq_pub: bytes | None = None

        if oqs is not None and _PQ_SIG_ALG is not None:
            sig = oqs.Signature(_PQ_SIG_ALG)
            pq_pub = sig.generate_keypair()
            pq_priv = sig.export_secret_key()

        return SigningKeyPair(ed_priv, ed_pub, pq_priv, pq_pub)

    @staticmethod
    def sign(message: bytes, private_key: SigningPrivateKey) -> bytes:
        """Format: [mode:1][ed25519_sig:64][pq_sig_if_hybrid]"""
        has_pq = private_key.pq_private is not None
        if has_pq and (oqs is None or _PQ_SIG_ALG is None):
            raise QBoostError("Hybrid private key requires oqs library for signing")

        mode = MODE_HYBRID if has_pq else MODE_CLASSICAL
        bound_msg = bytes([mode]) + message
        ed_sig = private_key.classical_private.sign(bound_msg)

        if has_pq:
            sig = oqs.Signature(_PQ_SIG_ALG, secret_key=private_key.pq_private)
            pq_sig = sig.sign(bound_msg)
            return bytes([mode]) + ed_sig + pq_sig

        return bytes([mode]) + ed_sig

    @staticmethod
    def verify(
        message: bytes, signature: bytes, public_key: SigningPublicKey
    ) -> bool:
        if len(signature) < 1 + _ED25519_SIG_LEN:
            return False

        mode = signature[0]
        ed_sig = signature[1 : 1 + _ED25519_SIG_LEN]
        bound_msg = bytes([mode]) + message

        if mode == MODE_CLASSICAL and public_key.pq_public is not None:
            return False

        ed_valid = True
        try:
            public_key.classical_public.verify(ed_sig, bound_msg)
        except Exception:
            ed_valid = False

        if mode == MODE_HYBRID:
            pq_sig = signature[1 + _ED25519_SIG_LEN :]
            if not pq_sig:
                return False
            if (
                public_key.pq_public is None
                or oqs is None
                or _PQ_SIG_ALG is None
            ):
                return False
            pq_valid = False
            try:
                verifier = oqs.Signature(_PQ_SIG_ALG)
                pq_valid = bool(verifier.verify(bound_msg, pq_sig, public_key.pq_public))
            except Exception:
                pq_valid = False
            return ed_valid and pq_valid

        return ed_valid and mode == MODE_CLASSICAL
