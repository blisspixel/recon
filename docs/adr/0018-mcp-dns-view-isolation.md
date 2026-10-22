# ADR-0018: Bind lower-trust collection to a caller-safe DNS view

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

A public-looking name can receive a private split-horizon answer from a
legitimate resolver. The CNAME walker can retain an additional alias that the
queried domain owner never supplied. Classified evidence and matching motifs
can expose that alias to a lower-trust MCP caller. Redaction alone leaves
record values, classifications, related lookups and query side effects.
HTTP name resolution independently used ambient OS DNS.

The maintainer selected protection for lower-trust callers on split-horizon
networks, while preserving ordinary `recon <domain>` with no new lookup flag,
wizard or recurring startup question. An arbitrary corporate resolver cannot
be certified caller-safe by inspecting its address or public-looking answers.

## Decision

Bind one immutable policy at MCP startup. Reuse saved approved configuration,
or recognize an explicitly configured published public resolver and use that
same service over authenticated DNS. Do not silently choose another provider
for an enterprise or forwarding-stub configuration. Missing or invalid approval
reports unavailable collection with concise one-time configuration guidance;
transport failure does not fall back to host DNS.

Use the existing dnspython resolver and its supported DoH/DoT transports. Fixed
numeric bootstrap addresses avoid ambient resolution of the resolver service;
TLS checks its configured identity. Task-local binding propagates to all DNS
record types, related enrichment and recursive chains, and the shared HTTP
admission/socket-resolution path. HTTP public-address admission and numeric
pinning remain mandatory in both trust modes.

Preserve trusted CLI host resolution. Advanced operator-view MCP requires
trusted saved configuration, a separate process/cache context and callers
authorized for that view. No tool argument, analytical profile or catalog
reload changes authority. Bind cache entries and retained results to policy
identity/version; expose only mode and opaque identity as provenance.

## Consequences

- Normal CLI UX is unchanged; MCP reuses approved configuration automatically.
- Public recursive DNS sees queried names. A new provider needs operator
  approval; encrypted transport alone is not authorization.
- Some enterprise environments need one-time server configuration. Missing
  approval cannot safely provide full collection; offline catalogs still work.
- The DoH extra adds HTTP/2 support to the existing DNS library rather than a
  second DNS implementation. Existing bounds, TLS checks and failure contracts
  remain blocking.
- Offline split-view, cache, HTTP admission and normal lookup regressions are
  required. Local verification is separate from release and deployment.
