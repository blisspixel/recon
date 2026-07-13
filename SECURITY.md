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
is authoritative; the scanner is likely lagging the repository.

## Scope

This policy covers the `recon-tool` Python package as distributed on PyPI,
including the CLI, `recon mcp`, and the bundled fingerprint/signal/profile
data files. It does not cover:

- Third-party services queried by the tool (Microsoft, Google, crt.sh, CertSpotter)
- User-created custom fingerprints, signals, or profiles
- Downstream integrations or wrappers

## Security Design Overview

recon is a defensive tool with a passive collection scope. It performs zero
active scanning, requires zero credentials, and makes zero authenticated
requests. DNS traffic may be visible to authoritative infrastructure; MTA-STS is
the one default target-owned HTTP request, and Google CSE or BIMI certificate
probes require explicit opt-in. The main security boundaries are local
execution, untrusted remote data, and MCP client behavior. For the deeper
engineering threat model, see `docs/security.md` and
`docs/adr/0011-public-metadata-collection-boundary.md`.

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
- Data-not-instructions demarcation: the injected server instructions tell the
  consuming model that every domain-derived string in tool output (DNS TXT,
  SPF / DMARC values, CT SAN names and issuer strings, BIMI metadata, identity-
  endpoint responses) is untrusted observed content, to be analyzed and
  reported as data and never followed as an instruction. This complements the
  output sanitization that removes terminal and markdown control sequences
  (v1.9.18 to v1.9.21); the demarcation covers the residual case where the
  literal observed text reads like a directive.

**Untrusted observed content (the conduit risk):**

recon is a conduit of attacker-influenceable strings into an LLM's context.
Whoever controls a queried domain's DNS or certificates controls the values
recon observes and returns. The mechanical injection surface (ANSI escapes,
newline and markdown injection, SSRF, ReDoS) was closed in the v1.9.18 to
v1.9.21 audit rounds. The residual surface is semantic: an observed value whose
plain text reads like an instruction. recon addresses that in-band, by marking
the observed content as data in the server instructions every session loads, so
a well-behaved consuming agent treats it accordingly. A consumer that
auto-approves tools should still treat all tool output as untrusted data.

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
