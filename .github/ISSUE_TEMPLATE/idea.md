---
name: Idea / feature request
about: Propose something larger than a fingerprint (new flag, MCP tool, CLI command, etc.)
title: "[Idea] "
labels: idea
---

> **Before filing:** most "I want recon to do X" ideas are better solved
> with a new fingerprint, signal, or profile; no code change is needed. See
> [CONTRIBUTING.md](../../CONTRIBUTING.md) for that path. File an idea
> issue only when the behavior you want genuinely requires engine changes.

## The idea in one sentence

What do you want recon to do that it doesn't do today?

## Why

What problem does this solve? Who feels the pain? How often?

## Invariant check

recon has a bounded public-metadata collection surface, requires zero
credentials, and keeps per-domain cache entries. Confirm the idea fits:

- [ ] Stays within public DNS, CT, unauthenticated identity discovery, default
      MTA-STS, and opt-in Google CSE or BIMI document fetches. It adds no
      arbitrary target HTTP request, port scan, service probe, or brute force.
      See [ADR-0011](../../docs/adr/0011-public-metadata-collection-boundary.md).
- [ ] Requires zero credentials, zero API keys, zero paid APIs.
- [ ] Does not introduce an aggregated local database, ML model,
      embedding, or ASN/GeoIP dataset.
- [ ] Is not already excluded by
      [Intentionally Not Doing](../../docs/roadmap.md#intentionally-not-doing)
      or the broader rejected-surface list in
      [CONTRIBUTING.md](../../CONTRIBUTING.md#whats-out-of-scope).
- [ ] Is not already shipped or represented by an active roadmap item.

If you ticked all five, continue. If any are unticked, the idea is likely
out of scope, but you can still file it with an explanation.

## Sketch

Rough design. What does the user experience look like? New flag? New
MCP tool? New field in `--json`? Something else?

## Alternatives considered

- Can this be done with a new fingerprint / signal / profile? (YAML path)
- Can this be done by piping `--json` into another tool?
- Is there an existing CLI flag that would serve?

If none of those work, explain why.

## Additional context

Any prior art, related tools, or fictionalized minimal cases that show where
this would help. Do not post real target output or private identifiers.
