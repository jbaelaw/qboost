# Security

QBoost is experimental and has **not** been independently audited.
Do not use it to protect real-world sensitive data without a thorough review.

| Component | Algorithm |
|---|---|
| KEM | X25519 + ML-KEM-768 |
| Signatures | Ed25519 + ML-DSA-65 |
| Symmetric | AES-256-GCM |
| KDF | Scrypt + SHAKE256 |

Report vulnerabilities via [GitHub Security Advisories](https://github.com/jbaelaw/qboost/security/advisories/new).
