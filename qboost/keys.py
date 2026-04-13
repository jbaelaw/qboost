from __future__ import annotations

import base64
import struct
import time

from .hybrid import HybridKEM, HybridKeyPair, HybridPrivateKey, HybridPublicKey
from .symmetric import decrypt as sym_decrypt
from .symmetric import encrypt as sym_encrypt
from .utils import QBoostError, sha3_256

_PUB_HEADER = b"QBOOST-PUB-V1\n"
_SEC_HEADER = b"QBOOST-SEC-V1\n"
_ENCRYPTED_PREFIX = b"ENC:"
_PLAIN_PREFIX = b"RAW:"


class QBoostPublicKey:
    def __init__(
        self,
        hybrid_public: HybridPublicKey,
        key_id: str | None = None,
    ):
        self.hybrid_public = hybrid_public
        self.key_id = key_id or _compute_key_id(hybrid_public)

    def __repr__(self) -> str:
        return f"QBoostPublicKey(id={self.key_id})"

    def serialize(self) -> bytes:
        return self.hybrid_public.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> QBoostPublicKey:
        hybrid_pub = HybridPublicKey.deserialize(data)
        return cls(hybrid_pub)

    @classmethod
    def from_export(cls, data: bytes) -> QBoostPublicKey:
        if not data.startswith(_PUB_HEADER):
            raise QBoostError("Invalid public key format")
        b64 = data[len(_PUB_HEADER) :]
        raw = base64.b64decode(b64)
        return cls.deserialize(raw)


class QBoostKeyPair:
    def __init__(
        self,
        hybrid_keypair: HybridKeyPair,
        created_at: float | None = None,
    ):
        self.hybrid = hybrid_keypair
        self.created_at = created_at or time.time()
        self.key_id = self._generate_key_id()

    def __repr__(self) -> str:
        return f"QBoostKeyPair(id={self.key_id})"

    def _generate_key_id(self) -> str:
        pub_bytes = self.hybrid.public_key.serialize()
        digest = sha3_256(pub_bytes)
        return digest[:16].hex()

    @property
    def public_key(self) -> QBoostPublicKey:
        return QBoostPublicKey(self.hybrid.public_key, self.key_id)

    def export_public_key(self) -> bytes:
        raw = self.hybrid.public_key.serialize()
        return _PUB_HEADER + base64.b64encode(raw)

    def export_private_key(self, password: str | None = None) -> bytes:
        priv_raw = self.hybrid.private_key.serialize()
        pub_raw = self.hybrid.public_key.serialize()
        raw = struct.pack(">H", len(priv_raw)) + priv_raw + pub_raw
        if password is not None:
            encrypted = sym_encrypt(raw, password)
            payload = _ENCRYPTED_PREFIX + base64.b64encode(encrypted)
        else:
            payload = _PLAIN_PREFIX + base64.b64encode(raw)
        return _SEC_HEADER + payload

    @classmethod
    def from_private_key(
        cls, data: bytes, password: str | None = None
    ) -> QBoostKeyPair:
        if not data.startswith(_SEC_HEADER):
            raise QBoostError("Invalid private key format")

        payload = data[len(_SEC_HEADER) :]

        if payload.startswith(_ENCRYPTED_PREFIX):
            if password is None:
                raise QBoostError("Password required to decrypt private key")
            encrypted = base64.b64decode(payload[len(_ENCRYPTED_PREFIX) :])
            raw = sym_decrypt(encrypted, password)
        elif payload.startswith(_PLAIN_PREFIX):
            raw = base64.b64decode(payload[len(_PLAIN_PREFIX) :])
        else:
            raise QBoostError("Unknown private key encoding")

        if len(raw) < 2:
            raise QBoostError("Invalid private key data")
        priv_len = struct.unpack(">H", raw[:2])[0]
        priv_raw = raw[2:2 + priv_len]
        pub_raw = raw[2 + priv_len:]

        hybrid_priv = HybridPrivateKey.deserialize(priv_raw)
        hybrid_pub = HybridPublicKey.deserialize(pub_raw)

        hybrid_kp = HybridKeyPair(
            hybrid_priv.classical_private,
            hybrid_pub.classical_public,
            hybrid_priv.pq_private,
            hybrid_pub.pq_public,
        )
        return cls(hybrid_kp)

    @classmethod
    def generate(cls) -> QBoostKeyPair:
        hybrid_kp = HybridKEM.generate_keypair()
        return cls(hybrid_kp)


def _compute_key_id(pub: HybridPublicKey) -> str:
    digest = sha3_256(pub.serialize())
    return digest[:16].hex()
