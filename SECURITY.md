# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in recon, please report it responsibly.

**Email:** nick@pueo.io

**Please include:**

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Please do not:**

- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before it has been addressed

## Response Timeline

- **Acknowledgment:** Within 48 hours of receipt
- **Assessment:** Within 7 days
- **Fix or mitigation:** Best effort, typically within 30 days for confirmed vulnerabilities

## Scope

This policy covers the `recon-tool` Python package and its dependencies as distributed on PyPI. It does not cover:

- Third-party services queried by the tool (Microsoft, Google, crt.sh, CertSpotter)
- User-created custom fingerprints, signals, or profiles
- Downstream integrations or wrappers

## Security Design

recon is a passive, read-only tool. It performs zero active scanning, requires zero credentials, and makes zero authenticated requests. The primary security considerations are:

- **SSRF protection** in the HTTP client (`recon_tool/http.py`)
- **ReDoS protection** via regex complexity validation on all fingerprint patterns
- **Input validation** on domain arguments before any network call
- **No secrets** — the tool never handles, stores, or transmits credentials

For the full threat model and attack surface documentation, see `docs/security.md` (planned for v1.0).
