# QBoost 🛡️

**Quantum-Boost Encryption Toolkit**

Simple, practical hybrid encryption that combines classical cryptography with quantum-resistant techniques.

[![CI](https://github.com/baejiho/qboost/actions/workflows/ci.yml/badge.svg)](https://github.com/baejiho/qboost/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Why QBoost?

Quantum computers threaten to break the public-key cryptography (RSA, ECDH) that secures almost everything online. "Harvest now, decrypt later" attacks mean that data encrypted today could be broken in the future.

QBoost takes a **hybrid approach**: every operation uses both a classical algorithm *and* a post-quantum algorithm. Your data stays secure as long as **either** one holds — no need to bet everything on a single new standard.

- **Without `oqs` installed** — QBoost uses X25519 with hash-based entropy enhancement, giving you strong classical security with extra hardening.
- **With `oqs` installed** — QBoost upgrades to true hybrid mode: X25519 + ML-KEM-768 (Kyber) for key exchange, Ed25519 + ML-DSA-65 (Dilithium) for signatures.

## Features

- 🔐 **Hybrid KEM** — X25519 + ML-KEM-768 (Kyber) key encapsulation
- ✍️ **Hybrid Signatures** — Ed25519 + ML-DSA-65 (Dilithium)
- 🔑 **Quantum-safe symmetric encryption** — AES-256-GCM with Scrypt + SHAKE256 key derivation
- 📦 **Zero-config** — works immediately, quantum-boost with `pip install oqs`
- 🐍 **Python 3.9+**

## Quick Start

### Installation

```bash
pip install qboost

# For full post-quantum support:
pip install qboost[pq]
```

### Encrypt & Decrypt with a Keypair

```python
import qboost

# Generate a keypair
keys = qboost.generate_keypair()

# Encrypt a message with the public key
message = b"Attack at dawn"
ciphertext = qboost.encrypt(message, keys.public_key)

# Decrypt with the keypair
plaintext = qboost.decrypt(ciphertext, keys)
assert plaintext == message
```

### Symmetric (Password-Based) Encryption

```python
import qboost

secret = b"Top secret plans"
password = "correct-horse-battery-staple"

ciphertext = qboost.encrypt_symmetric(secret, password)
plaintext = qboost.decrypt_symmetric(ciphertext, password)
assert plaintext == secret
```

### Signing & Verification

```python
from qboost import HybridSigner

# Generate signing keys
signing_keys = HybridSigner.generate_keypair()

# Sign a message
message = b"I approve this transaction"
signature = HybridSigner.sign(message, signing_keys.private_key)

# Verify
valid = HybridSigner.verify(message, signature, signing_keys.public_key)
assert valid
```

### Key Exchange Between Parties

```python
import qboost

# Alice generates a keypair and exports the public key
alice = qboost.generate_keypair()
alice_pub_export = alice.export_public_key()

# Bob imports Alice's public key and encrypts a message
ciphertext = qboost.encrypt(b"Hello Alice!", alice_pub_export)

# Alice decrypts
plaintext = qboost.decrypt(ciphertext, alice)
assert plaintext == b"Hello Alice!"
```

## How It Works

### Hybrid Key Encapsulation

QBoost performs a **dual KEM** (Key Encapsulation Mechanism):

1. **Classical** — An ephemeral X25519 Diffie-Hellman exchange produces a shared secret.
2. **Post-quantum** — An ML-KEM-768 (Kyber) encapsulation produces a second shared secret.
3. Both secrets are combined through HKDF-SHA256 to derive the final encryption key.

If `oqs` is not installed, step 2 is replaced with hash-based entropy enhancement using extra randomness encrypted under the classical key — still stronger than vanilla X25519.

### Hybrid Signatures

Signatures follow the same principle:

1. **Ed25519** produces a classical signature.
2. **ML-DSA-65** (Dilithium) produces a post-quantum signature.
3. Both signatures are concatenated. Verification requires both to pass.

### Security Model

QBoost follows a **"security holds if either primitive is secure"** design:

- The combined shared secret is derived from *both* the classical and PQ secrets via HKDF. An attacker must break **both** to recover the key.
- Symmetric encryption uses AES-256-GCM, which is already quantum-resistant (Grover's algorithm only halves the effective key length to 128-bit equivalent).
- Key derivation chains Scrypt (memory-hard) with SHAKE256 for defense in depth.

## API Reference

### Top-Level Functions

| Function | Description |
|---|---|
| `qboost.generate_keypair()` | Generate a new hybrid keypair (`QBoostKeyPair`) |
| `qboost.encrypt(plaintext, public_key)` | Encrypt bytes with a recipient's public key |
| `qboost.decrypt(ciphertext, private_key)` | Decrypt bytes with a keypair or private key |
| `qboost.encrypt_symmetric(plaintext, password)` | Password-based encryption (AES-256-GCM + Scrypt) |
| `qboost.decrypt_symmetric(ciphertext, password)` | Password-based decryption |
| `qboost.is_quantum_ready()` | `True` if `oqs` is installed and PQ algorithms are available |
| `qboost.info()` | Returns a dict with version and algorithm details |

### Key Classes

| Class | Description |
|---|---|
| `QBoostKeyPair` | Holds a hybrid keypair. Properties: `.public_key`, `.hybrid` |
| `QBoostKeyPair.export_public_key()` | Export public key as portable bytes |
| `QBoostKeyPair.export_private_key(password=None)` | Export private key (optionally password-protected) |
| `QBoostKeyPair.from_private_key(data, password=None)` | Import a keypair from exported private key bytes |
| `QBoostPublicKey` | A public key that can be shared with others |

### Signing

| Class / Method | Description |
|---|---|
| `HybridSigner.generate_keypair()` | Generate a hybrid signing keypair (`SigningKeyPair`) |
| `HybridSigner.sign(message, private_key)` | Sign a message |
| `HybridSigner.verify(message, signature, public_key)` | Verify a signature — returns `bool` |

### Symmetric Utilities

| Function | Description |
|---|---|
| `derive_key(password, salt=None)` | Derive a 32-byte key from a password (returns `(key, salt)`) |
| `encrypt_with_key(plaintext, key)` | Encrypt with a raw 32-byte key |
| `decrypt_with_key(ciphertext, key)` | Decrypt with a raw 32-byte key |

## Configuration

Check your current setup:

```python
import qboost

print(qboost.info())
# {'version': '0.1.0', 'pq_available': False, 'classical_kem': 'X25519',
#  'pq_kem': 'N/A (hash-enhanced)', 'symmetric': 'AES-256-GCM',
#  'kdf': 'Scrypt + SHAKE256'}

print("Quantum ready:", qboost.is_quantum_ready())
# Quantum ready: False  (install oqs for True)
```

## License

[MIT](LICENSE)
