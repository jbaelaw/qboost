# QBoost

Hybrid classical + post-quantum cryptographic toolkit for Python.

[![CI](https://github.com/jbaelaw/qboost/actions/workflows/ci.yml/badge.svg)](https://github.com/jbaelaw/qboost/actions/workflows/ci.yml)

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Security Considerations](#security-considerations)
- [Development](#development)
- [License](#license)

## Overview

QBoost is a hybrid cryptographic toolkit that combines classical algorithms (X25519, Ed25519, AES-256-GCM) with NIST-standardized post-quantum algorithms (ML-KEM-768, ML-DSA-65) in a defense-in-depth design. The library targets the "harvest now, decrypt later" threat, where adversaries collect encrypted traffic today with the expectation of decrypting it once cryptographically relevant quantum computers (CRQCs) become available.

The core design principle is dual-algorithm composition: every key encapsulation and digital signature operation combines a classical and a post-quantum primitive. Security holds if **either** component algorithm remains unbroken. This means QBoost provides at least the security level of the strongest individual primitive, regardless of which one is eventually compromised.

QBoost operates in two modes depending on the runtime environment. When the `oqs` library (liboqs-python) is installed, full hybrid mode engages ML-KEM-768 (FIPS 203) for key encapsulation and ML-DSA-65 (FIPS 204) for digital signatures alongside their classical counterparts. Without `oqs`, QBoost falls back to a classical-plus-hash-enhanced mode that still uses X25519 with additional entropy mixing via HKDF, providing a stronger-than-vanilla classical baseline while remaining fully operational.

## Architecture

### Cryptographic Stack

| Layer | Classical Algorithm | Post-Quantum Algorithm | Combined Via | Output |
|---|---|---|---|---|
| Key Encapsulation | X25519 ECDH | ML-KEM-768 (FIPS 203) | HKDF-SHA256 | 32-byte shared secret |
| Digital Signatures | Ed25519 | ML-DSA-65 (FIPS 204) | Concatenation | Combined signature blob |
| Symmetric Encryption | AES-256-GCM | -- | -- | Authenticated ciphertext |
| Key Derivation | Scrypt (n=2^16, r=8, p=1) | SHAKE256 | Sequential | 32-byte key |

### Ciphertext Format (Asymmetric)

```
[magic "QB1" : 3 bytes]
[KEM ciphertext length : 2 bytes, big-endian]
[KEM ciphertext : variable]
  [mode : 1 byte (0x01=classical, 0x02=hybrid)]
  [ephemeral X25519 public key : 32 bytes]
  [PQ ciphertext or encrypted entropy : variable]
[nonce : 12 bytes]
[AES-256-GCM ciphertext + tag : variable]
```

In hybrid mode, the KEM ciphertext contains the ML-KEM-768 ciphertext. In classical mode, it contains AES-256-GCM-encrypted random entropy that is mixed into the shared secret derivation via HKDF.

### Signature Format

```
[mode : 1 byte (0x01=classical, 0x02=hybrid)]
[Ed25519 signature : 64 bytes]
[ML-DSA-65 signature : variable, hybrid mode only]
```

### Key Serialization Format

```
Public key:  [mode:1][X25519 pub:32][PQ pub:variable if hybrid]
Private key: [mode:1][X25519 priv:32][PQ priv len:2][PQ priv:variable if hybrid]
```

### Key Export Format

```
Public:  QBOOST-PUB-V1\n + base64(serialized public key)
Private: QBOOST-SEC-V1\n + {RAW:|ENC:} + base64(length-prefixed priv + pub)
```

Private keys exported with a password use the `ENC:` prefix and are encrypted with the symmetric password-based scheme (Scrypt + SHAKE256 + AES-256-GCM). Keys exported without a password use `RAW:`.

### Symmetric Ciphertext Format (Password-Based)

```
[salt : 32 bytes]
[nonce : 12 bytes]
[AES-256-GCM ciphertext + tag : variable]
```

### Symmetric Ciphertext Format (Raw Key)

```
[nonce : 12 bytes]
[AES-256-GCM ciphertext + tag : variable]
```

## Installation

```bash
pip install qboost          # classical + hash-enhanced mode
pip install qboost[pq]      # full post-quantum via liboqs
```

**Requirements:**

- Python >= 3.9
- `cryptography` >= 42.0.0

**Optional:**

- `oqs` (liboqs-python) -- enables ML-KEM-768 and ML-DSA-65 for full hybrid mode

## Usage

### Asymmetric Encryption

```python
import qboost

keypair = qboost.generate_keypair()
ciphertext = qboost.encrypt(b"plaintext", keypair.public_key)
plaintext = qboost.decrypt(ciphertext, keypair)
```

### Symmetric Encryption

```python
import qboost

ciphertext = qboost.encrypt_symmetric(b"plaintext", "password")
plaintext = qboost.decrypt_symmetric(ciphertext, "password")
```

### Digital Signatures

```python
from qboost import HybridSigner

kp = HybridSigner.generate_keypair()
sig = HybridSigner.sign(b"message", kp.private_key)
valid = HybridSigner.verify(b"message", sig, kp.public_key)
```

### Key Export and Exchange

```python
import qboost
from qboost import QBoostPublicKey

alice = qboost.generate_keypair()
pub_export = alice.export_public_key()              # portable bytes
priv_export = alice.export_private_key("password")  # password-protected

# Reconstruct from exports
bob_pub = QBoostPublicKey.from_export(pub_export)
ct = qboost.encrypt(b"message", bob_pub)

restored = qboost.QBoostKeyPair.from_private_key(priv_export, "password")
pt = qboost.decrypt(ct, restored)
```

### Runtime Introspection

```python
import qboost

qboost.is_quantum_ready()  # True if oqs is available
qboost.info()              # dict with algorithm details
```

`info()` returns a dictionary of the form:

```python
{
    "version": "0.8.0",
    "pq_available": True,
    "classical_kem": "X25519",
    "pq_kem": "ML-KEM-768",       # or "N/A (hash-enhanced)" without oqs
    "symmetric": "AES-256-GCM",
    "kdf": "Scrypt + SHAKE256",
}
```

## API Reference

### Top-Level Functions

| Function | Parameters | Returns | Description |
|---|---|---|---|
| `generate_keypair()` | -- | `QBoostKeyPair` | Generate a hybrid keypair (X25519 + ML-KEM-768 if available) |
| `encrypt(pt, pub)` | `bytes`, `QBoostPublicKey \| bytes` | `bytes` | Hybrid KEM + AES-256-GCM encryption |
| `decrypt(ct, priv)` | `bytes`, `QBoostKeyPair \| HybridPrivateKey` | `bytes` | Decrypt ciphertext produced by `encrypt` |
| `encrypt_symmetric(pt, pw)` | `bytes`, `str` | `bytes` | Scrypt + SHAKE256 key derivation, then AES-256-GCM |
| `decrypt_symmetric(ct, pw)` | `bytes`, `str` | `bytes` | Symmetric decryption |
| `is_quantum_ready()` | -- | `bool` | Check if `oqs` is available at runtime |
| `info()` | -- | `dict` | Algorithm configuration and version details |

### Key Management Classes

| Class | Key Methods |
|---|---|
| `QBoostKeyPair` | `.generate()`, `.public_key`, `.export_public_key()`, `.export_private_key(password=None)`, `.from_private_key(data, password=None)`, `.key_id`, `.created_at` |
| `QBoostPublicKey` | `.serialize()`, `.deserialize(data)`, `.from_export(data)`, `.key_id` |

`QBoostKeyPair.generate()` is the class-level factory; the top-level `generate_keypair()` delegates to it. The `.key_id` property is derived from the SHA3-256 hash of the serialized public key (first 16 bytes, hex-encoded).

The `encrypt()` function accepts `QBoostPublicKey` objects directly, or raw `bytes` -- either serialized public key bytes or `QBOOST-PUB-V1` export format. Format is auto-detected.

### Hybrid KEM

| Class | Key Methods |
|---|---|
| `HybridKEM` | `.generate_keypair() -> HybridKeyPair`, `.encapsulate(pub) -> (secret, ct)`, `.decapsulate(ct, priv) -> secret` |

All methods are static. `encapsulate` generates an ephemeral X25519 keypair, performs ECDH against the recipient's public key, then (in hybrid mode) also encapsulates against the ML-KEM-768 public key. The two shared secrets are concatenated and passed through HKDF-SHA256 with the domain string `qboost-hybrid-kem-v1`.

In classical mode, 32 bytes of random entropy are encrypted under a separate HKDF-derived key (domain string `qboost-entropy-wrap-v1`) and mixed into the final HKDF derivation alongside the ECDH shared secret.

### Digital Signatures

| Class | Key Methods |
|---|---|
| `HybridSigner` | `.generate_keypair() -> SigningKeyPair`, `.sign(msg, priv) -> bytes`, `.verify(msg, sig, pub) -> bool` |

All methods are static. In hybrid mode, both Ed25519 and ML-DSA-65 signatures are produced and concatenated. Verification requires both signatures to be valid. A classical-mode signature is rejected if the public key is a hybrid key, preventing downgrade attacks.

### Symmetric Utilities

| Function | Parameters | Returns | Description |
|---|---|---|---|
| `derive_key(password, salt=None, key_length=32)` | `str`, `bytes \| None`, `int` | `tuple[bytes, bytes]` | Scrypt + SHAKE256 key derivation; returns `(key, salt)` |
| `encrypt_with_key(pt, key)` | `bytes`, `bytes` | `bytes` | AES-256-GCM encryption with a 32-byte key |
| `decrypt_with_key(ct, key)` | `bytes`, `bytes` | `bytes` | AES-256-GCM decryption with a 32-byte key |

`derive_key` first runs Scrypt (n=2^16, r=8, p=1) on the password, then passes the Scrypt output concatenated with the salt and the domain string `qboost-kdf-v1` through SHAKE256 to produce the final key.

### Exceptions

| Exception | Parent | Description |
|---|---|---|
| `QBoostError` | `Exception` | Base exception for all QBoost errors |
| `DecryptionError` | `QBoostError` | Raised on decryption or verification failure |

## Security Considerations

- The hybrid design ensures security if **either** the classical or post-quantum component remains unbroken.
- Signature verification rejects classical-mode signatures against hybrid public keys to prevent downgrade attacks.
- HKDF derivations use distinct domain-separation strings (`qboost-hybrid-kem-v1` for shared secret derivation, `qboost-entropy-wrap-v1` for entropy wrapping) to prevent cross-protocol attacks.
- AES-256-GCM provides 128-bit post-quantum security (Grover's algorithm halves the effective key length).
- Scrypt with memory-hard parameters (n=2^16, r=8, p=1) followed by SHAKE256 post-mixing resists GPU/ASIC brute force and preimage attacks on the KDF output.
- The `quantum_random` function uses `os.urandom` (the OS CSPRNG), not a quantum random source. The name reflects intent, not implementation.
- This library has **not** been independently audited. Not recommended for production use without review.

## Development

```bash
git clone https://github.com/jbaelaw/qboost.git
cd qboost
pip install -e ".[dev]"
pytest
```

To run with full post-quantum support:

```bash
pip install -e ".[dev,pq]"
pytest
```

## License

MIT -- Team JRTI
