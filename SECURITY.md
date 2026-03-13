# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in SaladVault, please report it responsibly.

**Email:** [security@saladvault.com](mailto:security@saladvault.com)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to expect

- **Acknowledgment** within 48 hours
- **Assessment** within 7 days
- **Resolution target** within 90 days (depending on severity)
- Credit in the release notes (unless you prefer anonymity)

### Scope

- SaladVault desktop application (Tauri)
- SaladVault API server
- Cryptographic implementations (Argon2id, XChaCha20-Poly1305, HKDF, HMAC)
- Authentication and session management
- Data storage and encryption at rest

### Out of scope

- Social engineering attacks
- Denial of service attacks
- Vulnerabilities in third-party dependencies (report these upstream, but let us know)

### Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Act in good faith to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts they own or with explicit permission
- Report vulnerabilities promptly and do not exploit them beyond proof of concept

**Please do NOT open a public GitHub issue for security vulnerabilities.**
