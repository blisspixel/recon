# Roadmap

This file is forward-looking. Shipped work belongs in
[CHANGELOG.md](../CHANGELOG.md); release mechanics belong in
[release-process.md](release-process.md).

Current release: **v1.6.1**. Current theme: treat correlation as inference
over a graph of strictly public observables (DNS, CT, identity-discovery
endpoints), keep every output hedged with full provenance, and let live
validation against a private corpus drive what ships next.

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

## What recon can and can't do against a hardened target

Honest framing: a disciplined paranoid setup — wildcard certs everywhere,
short-lived rotation, multi-hop randomized proxy chains, decoy noise, minimal
public DNS, hardened IdP metadata — will always produce sparse, low-confidence
output. That is physics, not a bug. The "obscurity is not security" critique
cuts both ways: a defender can choose to publish very little, and recon will
report very little.

What we can do better is make the residual signal go further. Wildcard certs
still leak sibling SAN sets within the same issuance batch. Short-lived certs
still land in CT logs with timestamps. Randomized CNAME chains still expose
recurring proxy motifs and intermediate-vendor markers. Multi-hop chains have
structure even when individual hops look bespoke. Treating the noisy
remainder as an inference problem — graph structure, temporal proximity,
chain motif libraries, vertical baselines — recovers usable defensive
intelligence that single-hop fingerprinting misses, while staying inside the
invariants. The "Ideas Worth Prototyping" table below lists the concrete
extensions, each gated by the same live-validation discipline.

## Current Fingerprint Library Assessment

As of v1.6.1, built-in fingerprints live in nine categorized YAML files:
`ai.yaml`, `crm-marketing.yaml`, `data-analytics.yaml`, `email.yaml`,
`infrastructure.yaml`, `productivity.yaml`, `security.yaml`, `surface.yaml`
(per-subdomain CNAME-target classification, added in v1.5), and
`verticals.yaml`.

Current no-network catalog audit:

- 346 fingerprint entries across 282 unique slugs (slugs may appear in
  multiple files when, e.g., `surface.yaml` extends an apex fingerprint
  with `cname_target` rules under the same name).
- 485 detection rules total, of which 163 are `cname_target` rules driving
  the surface-attribution pipeline.
- 97 multi-detection fingerprints.
- All built-ins currently use `match_mode: any`.
- Metadata coverage: 187/485 detections have descriptions, 9/485 have
  references, and 4/485 use non-default weights. Description coverage
  remains the largest gap; raise it before the catalog grows further.

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
- Multi-signal correlation depth: share of `--explain` outputs whose evidence
  DAG references more than one source per high-confidence slug. Useful as a
  proxy for "did our correlation engine do something single-source detection
  could not?"
- For experimental Bayesian or community-detection output: average posterior
  entropy reduction (or modularity score) per domain on the private corpus,
  tracked across releases. Trend matters more than absolute number.

## Next Work

| Lane | Status | Next concrete work | Done when |
|---|---|---|---|
| Live validation | Active | Run the private corpus through `validation/scan.py` on a regular cadence (weekly during active iteration, monthly otherwise). Each scan produces `results.ndjson`, `gaps.json`, `candidates.json`, and `diff.json` against the prior run. Triage candidates with the `/recon-fingerprint-triage` skill; turn high-confidence findings into `cname_target` (or other) rules. | Surfaced candidates either land in a fingerprint YAML with a corpus-delta note, or are explicitly recorded as out-of-scope (intra-org, niche one-off, can't-tell). |
| Fingerprint precision | Active | Walk the multi-detection backlog with the audit tooling, prioritizing identity, security, email, and infrastructure. Keep `tighten_patterns` at zero. | A small batch of high-value fingerprints per release is converted to `match_mode: all`, tightened, or explicitly kept `any` with rationale and before/after validation notes. |
| Sparse-result diagnosis | Active | Keep sparse public-signal output clear and tied to [weak-areas.md](weak-areas.md); add weak-area notes when fingerprint work exposes common false negatives. | Thin results explain the likely passive-observation ceiling instead of looking like a broken run, and every sparse class has a docs anchor or validation note. |
| Correlation depth | Planned | Promote one item from the "Ideas Worth Prototyping" table per release window. Start with the low-effort/high-validation entries (wildcard SAN siblings, temporal CT bursts, motif library). Each promotion follows the implementation-discipline checklist below. | The promoted feature ships as a YAML schema extension with corpus-delta evidence, hedged output language, and full DAG provenance. |
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
- Add one entry to a new `motifs.yaml` describing a recurring CNAME or NS
  chain pattern (e.g., `cloudflare → akamai → custom-origin`) with a
  before/after corpus delta showing the pattern actually fires.
- Add one vertical-baseline absence rule in `verticals.yaml` with a clear
  passive-ceiling note (e.g., "fintech profile expects WAF motif; absence
  is observable, not a verdict").
- Implement one Bayesian CPT in a draft `bayesian_network.yaml` covering
  email security + M365 federation, with the schema marked EXPERIMENTAL and
  the output gated behind the existing `--fusion` flag.

## Ideas Worth Prototyping

These are not commitments. Each must clear the invariants above and show real
validation value (corpus delta + schema validation + sparse-result language
audit) before becoming scoped work. Items higher in the table are the
near-term candidates; items lower are speculative.

| Idea | Interest | Validation value | Effort | Main risk |
|---|---:|---:|---:|---|
| Wildcard SAN sibling expansion | High | High | Low | crt.sh response shape variability; siblings must stay hedged as "issued together, ownership not implied". |
| Temporal CT issuance burst detection | High | High | Low | Clock skew on crt.sh timestamps; output must use relative deltas with explicit window, never absolute "same owner" verdicts. |
| CNAME / NS chain motif library (`motifs.yaml`) | High | High | Low | Motif explosion if cap is removed; constrain to chain length ≤ 4 and require live corpus delta before merge. |
| Cross-source evidence conflict surfacing | Medium | High | Low | Already partially tracked in `MergeConflicts`; needs `--explain` and JSON exposure plus a docs note on what conflicts mean. |
| CT co-occurrence graph + community detection | High | High | Medium | Graph size on large batches; cap at ~500 nodes per cluster pass with deterministic fallback to existing simple clustering. New `networkx` dep is acceptable (pure Python, widely vetted). |
| Vertical-baseline anomaly rules | Medium | High | Low | Easy to drift into recommendation overreach; rules must remain neutral observations tied to existing `verticals.yaml` profiles. |
| Bayesian fusion (small CPTs in YAML, credible intervals) | Medium | High | Medium | Experimental field shape must not destabilize the v1.0 JSON contract; ship behind `--fusion` (already exists) and gate output as EXPERIMENTAL. CPTs stay small (≤20 nodes), human-readable, and committed as data files — never learned weights. |
| Hypergraph ecosystem view (batch-only) | High | High | Medium | JSON size; surface only behind `--include-ecosystem`. Hyperedges describe shared issuer + shared fingerprint set + shared BIMI VMC organization — observations, not ownership. |
| BIMI VMC legal-name clustering | High | High | Medium | Low coverage; must stay hedged as "possible relationship". Pairs naturally with the hypergraph view above. |
| Fingerprint relationship metadata | Medium | High | Medium | Requires a stable-schema proposal; relationship edges must describe observations, not ownership verdicts. Subsumes part of the motif and co-occurrence work. |
| CT organization-name search | Medium | Medium | Medium | crt.sh reliability and stale certificate noise; should be exact and opt-in. |
| Feedback-driven posterior tuning | Medium | Medium | Medium | Local-only design must not become a shared reputation database. Pairs with the Bayesian layer; never ship learned weights, only the corpus that informed local priors. |
| MCP delta helper | Medium | Medium | Medium | Must compare supplied or cached JSON only; no hidden network fan-out. |
| Wayback Machine temporal enrichment | Medium | Medium | Medium | Adds a new public network surface and historical-data ambiguity; must be opt-in. |
| Deeper hardening simulation UX | Low | Low | High | Easy to drift from observation into recommendation overreach. |

## Opportunistic Refactoring

`formatter.py`, `server.py`, and `cli.py` carry disproportionate maintenance
burden. Split them when a feature or bug fix naturally opens the seam; do not
create a standalone refactor milestone without behavioral payoff.

## Intentionally Out Of Scope

**Hard no:** active scanning, paid APIs, credentialed access, bundled ML or
embedding weights, bundled ASN/GeoIP datasets, aggregate local databases,
user-code plugins, remote/HTTP MCP transport. The Bayesian and graph
extensions stay inside the box because they ship as data-file CPTs and
algorithms over already-collected observables — never as learned weights or
imported intelligence.

**Not this tool:** company research, firmographic enrichment, news/funding
feeds, hiring signals, GTM briefings, contact data, maturity scores, HTML
dashboards, TUI, REPL, daemon mode, scheduled monitoring, STIX/Maltego/MISP
exports, Prometheus metrics, Docker image, Homebrew tap, PDF reports.

Use `--json` (or `--ndjson` for big batches) as the integration surface. If
you need rendered graphs, reports, SIEM ingestion, or company research, pipe
recon output into a tool built for that job.

## Design Choices That Stay

- No confident "maturity" or "zero-trust" verdicts on sparse data.
- No generic subdomain service-name matching such as `grafana.*` or `n8n.*`.
- No ownership or acquisition verdicts from shared tokens or branding.
- No posture or insights layer may trigger a new network call.
- Delta mode reports raw changes; users decide what story, if any, those
  changes imply.
- Correlation extensions describe **observed structure**, not ownership.
  "Co-issued within 60s" is observable; "same owner" is not. Cluster output
  surfaces modularity scores and edge evidence, never verdicts. Bayesian
  layer surfaces credible intervals and the CPT that produced them, never
  point scores without provenance.

## Implementation discipline for new correlation work

Any item promoted from "Ideas Worth Prototyping" into shipped behavior must:

1. Land first as a YAML schema extension (signals, fingerprints, motifs, or
   a new sibling file). Engine code grows only when the data file alone
   cannot express the rule.
2. Carry a live-corpus before/after delta in the PR description, run on
   the private validation corpus with the discovery loop tooling
   (`validation/scan.py`, `find_gaps.py`, `triage_candidates.py`).
3. Document the sparse-result behavior — when this rule does NOT fire and
   why — alongside the positive case. Output language must remain hedged
   under sparse evidence even when the new feature surfaces nothing.
4. Update `docs/recon-schema.json` and the schema drift test if the JSON
   shape changes. Mark experimental fields explicitly; the v1.0 contract
   stays narrow and stable.
5. Stay deterministic when possible. Where probabilistic output is
   appropriate (Bayesian layer), gate behind an existing flag, mark
   EXPERIMENTAL, and never destabilize the default panel.
