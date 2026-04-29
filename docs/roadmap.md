# Roadmap

This file is forward-looking. Shipped work belongs in
[CHANGELOG.md](../CHANGELOG.md); release mechanics belong in
[release-process.md](release-process.md).

Current release: **v1.4.7**. Current theme: keep the public surface stable,
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

It is also meant to be useful to security teams, compliance analysts, vendor
due-diligence practitioners, IT architects, and AI-agent workflows that need
clean, provenance-rich public-signal visibility. The right mental model is a
composable building block, not a standalone source of truth.

## Current Fingerprint Library Assessment

As of v1.4.4, built-in fingerprints live in eight categorized YAML files:
`ai.yaml`, `crm-marketing.yaml`, `data-analytics.yaml`, `email.yaml`,
`infrastructure.yaml`, `productivity.yaml`, `security.yaml`, and
`verticals.yaml`.

Current no-network catalog audit:

- 227 fingerprints and 320 detection rules.
- 68 multi-detection fingerprints.
- All built-ins currently use `match_mode: any`.
- Match-mode audit queue: 45 `keep_any`, 23 `review_for_all`, and 0
  `tighten_patterns`.
- Metadata coverage: 106/320 detections have descriptions, 9/320 have
  references, and 4/320 use non-default weights.

What is good:

- The per-category YAML split is easy to review and contributor-friendly.
- Most high-confidence entries use service-specific TXT, MX, CNAME, NS, SRV,
  CAA, SPF, or `subdomain_txt` evidence instead of generic subdomain labels.
- Multi-signal support, detection weights, descriptions, references,
  `recon fingerprints new`, and `recon://fingerprints` already exist.
- The posture and signal layers consume fingerprint slugs as neutral
  observations, which keeps the output factual instead of prescriptive.
- Validation tooling now has both live-corpus comparison and a match-mode audit
  path, so catalog changes can be reviewed as evidence decisions.

What is missing or high ROI:

- Metadata consistency is uneven. Description and reference coverage should
  rise before the catalog gets much larger.
- The `review_for_all` queue needs manual validation. Identity, security, and
  infrastructure fingerprints should be prioritized because false positives
  there have the highest downstream cost.
- Keep the `tighten_patterns` queue at zero by tightening generic substrings
  before merge, especially on infrastructure and email-deliverability entries.
- Under-covered breadth remains in newer AI platforms, enterprise data/BI,
  SASE/SSE, payment/commerce, HR/operations, and vertical-specific tooling.
- Common false-negative configurations should be captured in
  [weak-areas.md](weak-areas.md) or PR notes so sparse results become easier to
  explain.
- New relationship-oriented metadata such as product families or co-location
  edges would require an explicit schema proposal; do not smuggle unsupported
  fields into YAML.

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

## Success Metrics (Post-1.0)

These are directional measures, not product OKRs:

- Share of high-value multi-detection fingerprints with an explicit
  `keep_any`, `match_mode: all`, or `tighten_patterns` decision backed by
  validation notes.
- Detection metadata coverage: descriptions, public references where available,
  and deliberate non-default weights.
- Quality of sparse-result explanations in live validation summaries, especially
  links to known passive-observation ceilings.
- Stability of JSON and MCP consumption examples against the documented schema.
- Sustainable community fingerprint PRs that pass schema, specificity, and
  validation gates without maintainer guesswork.

## Next Work

| Lane | Status | Next concrete work | Done when |
|---|---|---|---|
| Live validation | Active | Re-run the diverse corpus with `validation/run_corpus.py`; compare against the previous run; convert findings into focused fixes. Include the fingerprint audit summary with each run. | False-positive and false-negative findings are fixed, or documented as passive limits with sparse-result context in the validation summary. |
| Fingerprint precision | Active | Work the 23 `review_for_all` audit entries, prioritizing identity, security, email, and infrastructure. Keep `tighten_patterns` at zero. | 8-12 high-value fingerprints are converted to `match_mode: all`, tightened, or explicitly kept `any` with rationale and before/after validation notes. |
| Sparse-result diagnosis | Active | Keep sparse public-signal output clear and tied to [weak-areas.md](weak-areas.md); add weak-area notes when fingerprint work exposes common false negatives. | Thin results explain the likely passive-observation ceiling instead of looking like a broken run, and every sparse class has a docs anchor or validation note. |
| Release reliability | Active | Keep CI and release workflows aligned; release audits should inspect runtime dependencies, not the audit toolchain. | A tag-triggered release can run without diverging from main CI assumptions. |
| Docs cohesion | Active | Keep root docs conventional, project docs indexed, and counts/version references minimal outside this assessment. Add practical JSON/MCP examples for security review, compliance review, and agent analysis. | `docs/README.md` is the entry point, roadmap does not duplicate the changelog, and integration examples use only documented stable fields or clearly marked experimental fields. |

## Good First Roadmap Items

These are narrow, useful, and aligned with the product shape:

- Convert one ambiguous fingerprint to `match_mode: all`, with before/after
  evidence and a regression domain in local validation notes.
- Add one high-confidence fingerprint for a service that publishes a stable
  verification TXT, MX, CNAME, NS, SRV, or CAA pattern.
- Enrich 3-5 fingerprints in an under-described category with descriptions,
  public references where available, and tighter patterns.
- Improve a sparse-result explanation for a known weak area without adding new
  network calls.
- Add a short weak-area note when a fingerprint has common legitimate
  false-negative configurations.
- Add schema or docs examples that make existing behavior easier to consume in
  automation.
- Improve MCP resource consumption examples for `recon://fingerprints`,
  `recon://signals`, or `recon://profiles`; do not add network behavior.
- Add tests around parser, cache, MCP, or formatter edge cases discovered from
  real validation output.

## Ideas Worth Prototyping

These are not commitments. Each must clear the invariants above and show real
validation value before becoming scoped work.

| Idea | Interest | Validation value | Effort | Main risk |
|---|---:|---:|---:|---|
| BIMI VMC legal-name clustering | High | High | Medium | Low coverage; must stay hedged as "possible relationship". |
| CT organization-name search | Medium | Medium | Medium | crt.sh reliability and stale certificate noise; should be exact and opt-in. |
| Fingerprint relationship metadata | Medium | High | Medium | Requires a stable-schema proposal; relationship edges must describe observations, not ownership verdicts. |
| Feedback-driven posterior tuning | Medium | Medium | Medium | Local-only design must not become a shared reputation database. |
| Wayback Machine temporal enrichment | Medium | Medium | Medium | Adds a new public network surface and historical-data ambiguity; must be opt-in. |
| Bayesian fusion refinements | Medium | Medium | Medium | Experimental output must not destabilize the stable JSON contract. |
| MCP delta helper | Medium | Medium | Medium | Must compare supplied or cached JSON only; no hidden network fan-out. |
| Deeper hardening simulation UX | Low | Low | High | Easy to drift from observation into recommendation overreach. |

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
