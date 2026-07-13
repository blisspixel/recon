# ADR-0001: Strictly passive, zero-credential collection

- **Status:** Superseded by ADR-0011
- **Date:** 2025 (backfilled 2026-06-13)

## Context

recon answers "what does a domain's public surface reveal" for defensive review.
It could go deeper with active probing (port scans, login attempts) or
credentialed/paid data sources - but those change what the tool *is*: they cross
into intrusive territory, require trust and secrets, and make results
unreproducible by an outside reader. The product is trust, and for a security
tool aimed at defenders the collection method is part of the trust claim.

## Decision

We will collect **only** from passive, public, unauthenticated channels - DNS,
certificate-transparency logs, and providers' own unauthenticated identity
endpoints - with **zero credentials**, **no active scanning**, and **no paid
APIs or bundled intelligence databases**. The tool is a reducer over what the
public channel reveals, not an intelligence store.

## Consequences

- Every result is reproducible by anyone re-querying the same public sources;
  the empirical claims can be checked without our data.
- Ground truth is structurally unobservable and partly hideable, which forces
  the honest-uncertainty design (see ADR-0002) rather than confident verdicts.
- Some questions are simply unanswerable passively; recon says "we cannot tell"
  rather than reaching for an active or credentialed shortcut.
- This boundary is permanent, not version-gated: active scanning, credentials,
  paid APIs, and bundled baselines will not appear in any future major version.
