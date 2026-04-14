# Security Policy

## Disclosure

Report vulnerabilities via [GitHub Security Advisories](https://github.com/jbaelaw/qboost/security/advisories/new).
Do not open public issues for security vulnerabilities.

## Cryptographic Design

QBoost employs a dual-algorithm hybrid design. Security holds if either the classical
or the post-quantum primitive remains secure.

### Algorithms

| Layer | Classical | Post-Quantum | Standard |
|---|---|---|---|
| Key Encapsulation | X25519 | ML-KEM-768 | FIPS 203 |
| Digital Signatures | Ed25519 | ML-DSA-65 | FIPS 204 |
| Symmetric Cipher | AES-256-GCM | -- | NIST SP 800-38D |
| Key Derivation | Scrypt | SHAKE256 | NIST SP 800-185 |

### Threat Model

- Hybrid KEM: an attacker must break both X25519 and ML-KEM-768 to recover the shared secret.
- Hybrid Signatures: downgrade from hybrid to classical mode is detected and rejected.
- Symmetric: AES-256 provides 128-bit security against Grover's algorithm.
- KDF: Scrypt (n=2^16, r=8, p=1) with SHAKE256 post-mixing resists brute-force and preimage attacks.

### Known Limitations

- This library has not been independently audited.
- Side-channel resistance depends on the underlying `cryptography` and `oqs` libraries.
- The `quantum_random` function uses `os.urandom` (CSPRNG), not a quantum random source.

## Supported Versions

| Version | Status |
|---|---|
| 0.8.5+ | Current |
| < 0.8.5 | Unsupported |
