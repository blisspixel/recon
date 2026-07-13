# ADR-0011: Define the public-metadata collection boundary

- **Status:** Accepted
- **Date:** 2026-07-13
- **Supersedes:** ADR-0001

## Context

ADR-0001 established the permanent zero-credential, no-active-scanning
boundary. Its phrase "strictly passive" became too imprecise for the shipped
network behavior. DNS queries can be visible to recursive and authoritative
operators. A default lookup can fetch the standards-defined MTA-STS policy from
`mta-sts.{domain}`. Operators can explicitly enable Google CSE discovery and a
BIMI certificate fetch. These are bounded public-metadata requests, but some are
visible to infrastructure controlled by the queried domain.

The older statement that every result is reproducible by re-querying the same
sources also needs qualification. DNS, certificate transparency, provider
responses, caches, resolver vantage, and time can change. The method and output
contract are reproducible; an observation is not guaranteed to repeat later or
from another vantage.

## Decision

recon will remain passive in collection scope:

- no port scanning, service enumeration, login attempts, exploit checks,
  credential use, arbitrary application crawling, paid feeds, or bundled
  private-intelligence databases;
- default collection is limited to public DNS, certificate-transparency data,
  unauthenticated provider identity-discovery endpoints, and the published
  MTA-STS policy endpoint;
- Google CSE and BIMI certificate requests remain explicit opt-in direct probes;
- documentation must name target-visible interactions and must not imply that
  "passive" means invisible or that every observation is repeatable;
- outputs describe time- and vantage-bounded public observations, not verified
  operational state, ownership, authorization, or complete product use.

## Consequences

- The zero-credential and no-active-scanning product identity remains intact.
- Operators can make informed choices about query visibility and direct probes.
- Tests and docs must keep the default and opt-in network boundaries aligned.
- Reproducibility claims apply to deterministic local processing, schemas,
  fixtures, and documented methods. Live observations retain explicit temporal,
  cache, provider, and resolver-vantage limits.
- Any proposal for a new target-owned request requires a separate architecture
  decision, an explicit user-controlled boundary, and corresponding threat,
  privacy, documentation, and regression analysis.
