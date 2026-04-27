# Roadmap

This file is forward-looking. Shipped work belongs in
[CHANGELOG.md](../CHANGELOG.md); release mechanics belong in
[release-process.md](release-process.md).

Current release: **v1.4.3**. Current theme: keep the public surface stable,
raise evidence quality, and let live-validation findings drive changes.

## What recon is

recon is the **passive-DNS primitive**: given an apex domain, return hedged
observations about the organization's public technology stack and identity
posture using public DNS, certificate transparency, and unauthenticated
identity-discovery endpoints.

It is designed to be consumed by other tools — active scanners, company
research enrichers, GTM systems, agent workflows — not to become those tools.
Humility over completeness is the product line: if a feature would make sparse
evidence sound more certain than it is, it does not belong here.

## Invariants

- **Passive only.** No active scanning, port probes, zone transfers, or target
  TLS handshakes.
- **Zero credentials, zero API keys, zero paid APIs.** Every data source must
  be reachable without an account.
- **No bundled ML models, embeddings, ASN data, GeoIP data, or local aggregate
  intelligence database.**
- **No user-code plugin system.** Custom fingerprints, signals, and profiles
  are data files only.
- **Hedged output.** Sparse evidence stays qualified. Dense evidence can be
  firmer, but never absolute.
- **Neutral language.** Observable facts only. No offensive guidance, takeover
  hints, maturity verdicts, or timeline narratives.

Anything new must fit inside this box.

## Priority Order

Correctness → reliability → explainability → composability → new features.

Post-1.0, hardening existing behavior beats adding new surface. Data-file
growth is welcome; engine growth needs stronger justification.

## Next Work

| Lane | Status | Next concrete work | Done when |
|---|---|---|---|
| Live validation | Active | Re-run the diverse corpus with `validation/run_corpus.py`; compare against the previous run; convert findings into focused fixes. | False-positive and false-negative findings are either fixed or documented as passive limits. |
| Fingerprint precision | Active | Audit high-value single-pattern fingerprints and convert evidence-supported cases to `match_mode: all`. | 8-12 high-risk ambiguous fingerprints are chained or explicitly kept single-pattern with rationale. |
| Sparse-result diagnosis | Active | Keep sparse public-signal output clear and tied to [weak-areas.md](weak-areas.md). | Thin results explain the likely passive-observation ceiling instead of looking like a broken run. |
| Release reliability | Active | Keep CI and release workflows aligned; release audits should inspect runtime dependencies, not the audit toolchain. | A tag-triggered release can run without diverging from main CI assumptions. |
| Docs cohesion | Active | Keep root docs conventional, project docs indexed, and counts/version references minimal. | `docs/README.md` is the entry point, and roadmap does not duplicate the changelog. |

## Good First Roadmap Items

These are narrow, useful, and aligned with the product shape:

- Convert one ambiguous fingerprint to `match_mode: all`, with before/after
  evidence and a regression domain in local validation notes.
- Add one high-confidence fingerprint for a service that publishes a stable
  verification TXT, MX, CNAME, NS, SRV, or CAA pattern.
- Improve a sparse-result explanation for a known weak area without adding new
  network calls.
- Add schema or docs examples that make existing behavior easier to consume in
  automation.
- Add tests around parser, cache, MCP, or formatter edge cases discovered from
  real validation output.

## Ideas Worth Prototyping

These are not commitments. Each must clear the invariants above and show real
validation value before becoming scoped work.

| Idea | Interest | Effort | Main risk |
|---|---:|---:|---|
| BIMI VMC legal-name clustering | High | Medium | Low coverage; must stay hedged as "possible relationship". |
| CT organization-name search | Medium | Medium | crt.sh reliability and stale certificate noise. |
| Feedback-driven posterior tuning | Medium | Medium | Local-only design must not become a shared reputation database. |
| Wayback Machine temporal enrichment | Medium | Medium | Adds a new public network surface and historical-data ambiguity. |
| Bayesian fusion refinements | Medium | Medium | Experimental output must not destabilize the stable JSON contract. |
| Deeper hardening simulation UX | Medium | High | Easy to drift from observation into recommendation overreach. |

## Opportunistic Refactoring

`formatter.py`, `server.py`, and `cli.py` carry disproportionate maintenance
burden. Split them when a feature or bug fix naturally opens the seam; do not
create a standalone refactor milestone without behavioral payoff.

## Intentionally Out Of Scope

**Hard no:** active scanning, paid APIs, credentialed access, bundled ML or
embedding weights, bundled ASN/GeoIP datasets, aggregate local databases,
user-code plugins, remote/HTTP MCP transport.

**Not this tool:** company research, firmographic enrichment, news/funding
feeds, hiring signals, GTM briefings, contact data, maturity scores, HTML
dashboards, TUI, REPL, daemon mode, scheduled monitoring, STIX/Maltego/MISP
exports, Prometheus metrics, Docker image, Homebrew tap, PDF reports.

Use `--json` as the integration surface. If you need rendered graphs, reports,
SIEM ingestion, or company research, pipe recon output into a tool built for
that job.

## Design Choices That Stay

- No confident "maturity" or "zero-trust" verdicts on sparse data.
- No generic subdomain service-name matching such as `grafana.*` or `n8n.*`.
- No ownership or acquisition verdicts from shared tokens or branding.
- No posture or insights layer may trigger a new network call.
- Delta mode reports raw changes; users decide what story, if any, those
  changes imply.
