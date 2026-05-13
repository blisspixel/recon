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

## Closed audit findings

Findings reported by external audits, scanners, or security reviews are
tracked with closure receipts in
[`docs/security-audit-resolutions.md`](docs/security-audit-resolutions.md).
The file is keyed by *topic* rather than vendor-specific ID so the record
stays portable across audit tools, and it includes file:line receipts
plus closure commit SHAs for verification. If a scanner reports a
finding listed there as open, the closure status documented in that file
is authoritative — the scanner is likely lagging the repo.

## Scope

This policy covers the `recon-tool` Python package as distributed on PyPI,
including the CLI, `recon mcp`, and the bundled fingerprint/signal/profile
data files. It does not cover:

- Third-party services queried by the tool (Microsoft, Google, crt.sh, CertSpotter)
- User-created custom fingerprints, signals, or profiles
- Downstream integrations or wrappers

## Security Design Overview

recon is a passive, defensive tool. It performs zero active scanning, requires
zero credentials, and makes zero authenticated requests. The main security
boundaries are local execution, untrusted remote data, and MCP client behavior.
For the deeper engineering threat model, see `docs/security.md`.

## MCP Threat Model (core feature)

`recon mcp` is a local stdio JSON-RPC server started by AI clients such as
Claude, Cursor, or VS Code. It runs with the privileges of the calling
user/process.

**Assumptions we make:**

- The connected AI agent is untrusted or potentially adversarial.
- Prompt injection, tool poisoning, and parameter tampering are possible.
- Users may connect GUI clients that inherit broad filesystem and network access
  from the local desktop session.

**Mitigations already in place (v1.3.1+):**

- Ephemeral fingerprint cap (`_MAX_EPHEMERAL_FINGERPRINTS = 100`) enforced via
  `EphemeralCapacityError`
- Path containment via `Path.is_relative_to()` for the TenantInfo cache and CT
  cache
- Regex length cap plus the specificity gate on MCP-injected patterns
- PTR lookups skipped for private, loopback, link-local, reserved, and multicast
  IPs
- CT result accumulation hard caps to bound work on large or adversarial
  provider responses
- Bounded TTL cache and per-domain rate limiting in the MCP server to reduce
  repeated lookup abuse

**Remaining risks (users must understand):**

- Resource exhaustion is still possible within the configured per-session caps.
- Cache poisoning attempts remain possible if multiple untrusted agents share a
  config directory; prefer isolated `RECON_CONFIG_DIR` paths or disposable
  workspaces for agent runs.
- High-volume external queries (DNS, CT, Microsoft/Google identity endpoints)
  are rate-limited but still consume local and upstream resources.
- MCP clients can still request legitimate tool invocations you did not intend.
  Leave approvals manual by default and only expand allowlists deliberately.

**Recommended deployment posture:**

- For casual local use, run `recon mcp` with manual approvals.
- For production or semi-autonomous agent use, run it in an isolated workspace
  or container with filesystem and network restrictions.
- Review `docs/mcp.md` and `docs/security.md` before enabling any automatic MCP
  approvals.
