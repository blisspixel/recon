---
name: Idea / feature request
about: Propose something larger than a fingerprint (new flag, MCP tool, CLI command, etc.)
title: "[Idea] "
labels: idea
---

> **Before filing:** most "I want recon to do X" ideas are better solved
> with a new fingerprint, signal, or profile — no code change needed. See
> [CONTRIBUTING.md](../../CONTRIBUTING.md) for that path. File an idea
> issue only when the behavior you want genuinely requires engine changes.

## The idea in one sentence

What do you want recon to do that it doesn't do today?

## Why

What problem does this solve? Who feels the pain? How often?

## Invariant check

recon is strictly passive, zero-creds, per-domain storage. Confirm the
idea fits:

- [ ] Uses only public DNS / CT / unauthenticated Microsoft/Google
      identity endpoints. **No HTTP probes against target infrastructure.**
- [ ] Requires zero credentials, zero API keys, zero paid APIs.
- [ ] Does not introduce an aggregated local database, ML model,
      embedding, or ASN/GeoIP dataset.
- [ ] Not already on the "[Not this tool](../../docs/roadmap.md#intentionally-not-doing)"
      list (HTML output, web dashboard, `recon serve`, TUI, STIX/MISP
      exports, scheduled/daemon mode, Docker image, etc.).
- [ ] Not already in the roadmap as a post-1.0 idea (NetworkX graph,
      portfolio detection, temporal CT, Bayesian tuning, etc.).

If you ticked all five, continue. If any are unticked, the idea is likely
out of scope — but you can still file it with an explanation.

## Sketch

Rough design. What does the user experience look like? New flag? New
MCP tool? New field in `--json`? Something else?

## Alternatives considered

- Can this be done with a new fingerprint / signal / profile? (YAML path)
- Can this be done by piping `--json` into another tool?
- Is there an existing CLI flag that would serve?

If none of those work, explain why.

## Additional context

Any prior art, related tools, concrete domains where this would help, etc.
