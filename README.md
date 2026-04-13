# QBoost

Hybrid classical + post-quantum encryption toolkit for Python.

[![CI](https://github.com/jbaelaw/qboost/actions/workflows/ci.yml/badge.svg)](https://github.com/jbaelaw/qboost/actions/workflows/ci.yml)

## Install

```bash
pip install qboost
pip install qboost[pq]  # ML-KEM-768 + ML-DSA-65 via liboqs
```

## Usage

```python
import qboost

keys = qboost.generate_keypair()
ct = qboost.encrypt(b"secret", keys.public_key)
pt = qboost.decrypt(ct, keys)

qboost.encrypt_symmetric(b"secret", "password")
```

Signing:

```python
from qboost import HybridSigner

kp = HybridSigner.generate_keypair()
sig = HybridSigner.sign(b"msg", kp.private_key)
assert HybridSigner.verify(b"msg", sig, kp.public_key)
```

Key exchange between two parties:

```python
import qboost
from qboost import QBoostPublicKey

alice = qboost.generate_keypair()
pub_bytes = alice.export_public_key()

ct = qboost.encrypt(b"for alice", pub_bytes)
pt = qboost.decrypt(ct, alice)
```

## How it works

Every operation combines a classical algorithm with a post-quantum one.
Security holds if **either** primitive survives.

| Layer | Classical | Post-Quantum |
|---|---|---|
| KEM | X25519 | ML-KEM-768 (Kyber) |
| Signature | Ed25519 | ML-DSA-65 (Dilithium) |
| Symmetric | AES-256-GCM | — |
| KDF | Scrypt | SHAKE256 |

Without `oqs`, the PQ slot is replaced by hash-based entropy hardening —
still stronger than vanilla X25519.

```python
>>> qboost.info()
{'version': '0.7.0', 'pq_available': False, 'classical_kem': 'X25519', ...}
```

## API

`generate_keypair()` · `encrypt(pt, pub)` · `decrypt(ct, priv)` · `encrypt_symmetric(pt, pw)` · `decrypt_symmetric(ct, pw)` · `is_quantum_ready()` · `info()`

Key classes: `QBoostKeyPair` · `QBoostPublicKey` · `HybridSigner` · `HybridKEM`

See `examples/` for full usage patterns.

## License

MIT — Team JRTI
