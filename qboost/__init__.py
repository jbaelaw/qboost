"""QBoost - Quantum-Boost Encryption Toolkit"""
from __future__ import annotations

from .core import (
    decrypt,
    decrypt_symmetric,
    encrypt,
    encrypt_symmetric,
    generate_keypair,
    info,
    is_quantum_ready,
)
from .hybrid import HybridKEM, HybridKeyPair, HybridPrivateKey, HybridPublicKey
from .keys import QBoostKeyPair, QBoostPublicKey
from .signatures import HybridSigner, SigningKeyPair, SigningPrivateKey, SigningPublicKey
from .symmetric import decrypt_with_key, derive_key, encrypt_with_key
from .utils import VERSION, DecryptionError, QBoostError

__version__ = VERSION
__all__ = [
    "generate_keypair",
    "encrypt",
    "decrypt",
    "encrypt_symmetric",
    "decrypt_symmetric",
    "is_quantum_ready",
    "info",
    "QBoostKeyPair",
    "QBoostPublicKey",
    "HybridKEM",
    "HybridKeyPair",
    "HybridPublicKey",
    "HybridPrivateKey",
    "derive_key",
    "encrypt_with_key",
    "decrypt_with_key",
    "HybridSigner",
    "SigningKeyPair",
    "SigningPublicKey",
    "SigningPrivateKey",
    "VERSION",
    "QBoostError",
    "DecryptionError",
]
