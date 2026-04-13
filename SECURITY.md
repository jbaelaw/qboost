# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

## Reporting Vulnerabilities

If you discover a security vulnerability in QBoost, **please do not open a public issue**.

Instead, report it privately:

1. Email: Open a [GitHub Security Advisory](https://github.com/baejiho/qboost/security/advisories/new) (preferred).
2. Include: a description of the issue, steps to reproduce, and the potential impact.
3. You will receive an acknowledgment within 48 hours and a detailed response within 7 days.

We take all reports seriously. We will coordinate with you on disclosure timing.

## Security Model

QBoost uses a **hybrid cryptographic design** where security holds if **either** the classical or post-quantum primitive remains secure.

### Key Encapsulation (Encryption)

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Classical | X25519 (ECDH) | Elliptic-curve key agreement |
| Post-Quantum | ML-KEM-768 (Kyber) | Lattice-based KEM (NIST standard) |
| Key Derivation | HKDF-SHA256 | Combines both shared secrets |
| Fallback | Hash-enhanced X25519 | When `oqs` is not installed |

### Signatures

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Classical | Ed25519 | Elliptic-curve signatures |
| Post-Quantum | ML-DSA-65 (Dilithium) | Lattice-based signatures (NIST standard) |

### Symmetric Encryption

| Component | Algorithm | Details |
|-----------|-----------|---------|
| Cipher | AES-256-GCM | 256-bit key, authenticated encryption |
| KDF | Scrypt (n=2^16, r=8, p=1) | Memory-hard password derivation |
| Post-KDF | SHAKE256 | Additional key stretching |
| Nonce | 96-bit random | Fresh nonce per encryption |
| Salt | 256-bit random | Fresh salt per key derivation |

### Design Decisions

- **Dual KEM**: The final shared secret is derived from both classical and PQ shared secrets via HKDF. An attacker must break both to recover the key.
- **Authenticated encryption**: AES-256-GCM provides confidentiality and integrity.
- **Memory-hard KDF**: Scrypt protects passwords against GPU/ASIC brute-force attacks.
- **No algorithm negotiation**: There is no downgrade attack surface — the mode is determined by key type.

## Known Limitations

- **Not audited.** This library has not undergone a formal security audit. It is intended for research, prototyping, and educational purposes.
- **Side channels.** No specific countermeasures against timing or power analysis side channels have been implemented beyond what the underlying libraries (`cryptography`, `oqs`) provide.
- **PQ key recovery.** When exporting/importing private keys without the `oqs` library, PQ key material may not round-trip correctly. Always export both public and private keys together.
- **Quantum randomness.** The `quantum_random` function currently uses `os.urandom` (CSPRNG), not an actual quantum random source.

## Disclaimer

> **QBoost is experimental software.** It is NOT recommended for production use protecting real-world sensitive data without a thorough independent security review. The post-quantum algorithms used (ML-KEM-768, ML-DSA-65) are NIST standards, but their implementations via `liboqs` are still maturing. Use at your own risk.
