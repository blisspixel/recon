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
invariants.

Progress shows up as **multi-signal correlation depth**: `--explain`
outputs whose evidence DAG references more than one source per
high-confidence slug. The metric is tracked per release against the private
corpus (see Success Metrics) and is the lens we use to ask "did the new
correlation work do something single-source detection could not?". The
**Build plan** below lists the concrete extensions, each gated by the same
live-validation discipline.

See [correlation.md](correlation.md) for the formal latent-variable model
$G = (V, E, \Theta)$, the mutual-information objective, and the detailed
mapping of each planned extension (v1.7 through v1.9) to hardened-target
signal recovery.

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

- **Multi-signal correlation depth** — north-star metric. Share of
  `--explain` outputs whose evidence DAG references more than one source
  per high-confidence slug. The lens for "did the new correlation work
  do something single-source detection could not?". Tracked per release
  against the private corpus; explained in detail in
  [correlation.md](correlation.md).
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
- For experimental Bayesian or community-detection output: average posterior
  entropy reduction (or modularity score) per domain on the private corpus,
  tracked across releases. Trend matters more than absolute number.

## Build plan

The plan is grouped into a small number of meaningful releases, not a long
trail of patches. Each release ships as a complete unit: a coherent feature
set, a catalog growth pass, and a private-corpus validation run that proves
the new behavior on real targets. Build order respects dependencies — the
graph layer needs the signal coverage that comes before it; the
probabilistic layer needs the signals to feed posteriors. Patches happen
when something actually breaks, not as a way to chunk work.

Standing work that runs alongside every release:

- **Catalog growth.** Each release window includes at least one private-
  corpus scan with `validation/scan.py` against a 4k+ domain library,
  candidate triage via the `/recon-fingerprint-triage` skill, and the
  resulting `cname_target` (or other) rules merged with corpus-delta notes.
- **Fingerprint precision.** Walk the multi-detection backlog one batch
  per release; prioritize identity, security, email, infrastructure where
  false positives have the highest downstream cost.
- **Sparse-result diagnosis.** Every new feature documents its
  passive-observation ceiling. When the rule does not fire, output stays
  hedged and the user understands why.
- **Release and docs reliability.** CI gates cover the same checks as
  release; counts and version references stay tight to this file.

### v1.7.0 — Hardened-target signal recovery

Squeeze more out of CT logs and resolution chains, and surface what we
already track but don't expose. Everything in this release lands as a YAML
data file plus minimal engine extension.

- **Wildcard SAN sibling expansion.** When `*.example.com` appears in a
  cert, harvest every other SAN from the same cert as a candidate sibling.
  No new network surface — uses the existing CT response and DNS resolver.
- **Temporal CT issuance bursts.** Use the `not_before` timestamps already
  in the CT response. Co-issued subdomains within a short window become
  `temporal_motif: deployment_burst` evidence. Output uses relative deltas
  and an explicit window; no absolute "same owner" claims.
- **CNAME / NS chain motif library (`motifs.yaml`).** Data file describing
  recurring proxy patterns (`cloudflare → akamai → custom-origin`,
  `fastly → azure`, etc.). Chain length capped at 4. Pattern matching
  hooks into the existing chain parser.
- **Cross-source evidence conflict surfacing.** `MergeConflicts` already
  records contradictions between sources. Expose them as a top-level
  `evidence_conflicts` array in `--json` and a section in `--explain`.

**Validation gate** — full private corpus scan after merge; gaps and
candidates archived under `validation/runs-private/v170/`. Sparse-result
language audit: every new rule has a documented "does not fire when…"
case alongside the positive case.

### v1.8.0 — Graph correlation

Build the structural layer. The wildcard-sibling and burst-detection work
in v1.7 produces edge-quality CT data; v1.8 turns it into community
structure and ecosystem views.

- **CT co-occurrence graph + community detection.** Build an in-memory
  graph from shared cert / issuer + temporal-window evidence. Run Leiden
  community detection (pure-Python `networkx`, new dependency). Output a
  top-level `infrastructure_clusters` array with modularity score and per-
  cluster edge evidence. Cap graph size at ~500 nodes per cluster pass
  with deterministic fallback to existing simple clustering.
- **Fingerprint relationship metadata.** Schema extension allowing each
  fingerprint to declare relationship hints (product family, parent
  vendor, BIMI org). Drives ecosystem aggregation in batch mode without
  asserting ownership.
- **Hypergraph ecosystem view (batch-only).** Behind
  `--include-ecosystem`. Hyperedges: shared issuer + shared fingerprint
  set + shared BIMI VMC organization. Surfaces multi-brand orgs that
  single-domain views miss.
- **Vertical-baseline anomaly rules.** Extend `verticals.yaml` and
  `absence.py` to flag deviations from per-profile expectations
  (e.g. fintech profile expects WAF motif; absence is observable, not a
  verdict).
- **Graph export MCP tool.** Add `get_infrastructure_clusters` (and an
  `export_graph` companion for the raw co-occurrence edges) that returns
  the already-computed cluster output and modularity scores. Read-only,
  no new network surface — just exposes what the deterministic graph pass
  produced so agents and downstream tools can reason over the structure
  without re-deriving it.

**Validation gate** — full corpus scan with `--include-ecosystem`;
cluster modularity scores tracked across the run and compared to v1.7.0
baseline. Anomaly rules tested against vertical-segmented subsets of the
corpus to confirm sensitivity without over-alerting.

### v1.9.0 — Probabilistic fusion (experimental)

Layer Bayesian inference on top of the deterministic engine. Existing
deterministic rules still run first; the Bayesian layer updates posteriors
and adds credible intervals. Gate behind the existing `--fusion` flag and
mark output EXPERIMENTAL until at least two corpus runs validate
calibration.

- **Bayesian network in `bayesian_network.yaml`.** Nodes are fingerprint
  slugs and signals; edges are conditional probability tables. Network
  stays small (≤20 nodes per per-domain inference), human-readable, and
  committed as data — never learned weights. Exact inference via variable
  elimination.
- **Calibrated posteriors with explicit passive-ceiling language.** The
  experimental output path emits a credible interval per slug instead of
  a point score. `PostureObservation` gains a posterior + interval field;
  the v1.0 default JSON shape is untouched. Sparse-evidence cases produce
  wider intervals and surface the passive-observation ceiling directly in
  the explanation, instead of letting a hedged-but-confident-looking
  number imply more than the evidence supports.
- **Cross-source conflict resolution feeding posterior.** Conflicts
  surfaced in v1.7 become probabilistic dampeners on the affected slugs.
- **Feedback-driven priors (local only).** Validation runs can update a
  local prior file in `~/.recon/priors.yaml`; never shared, never shipped
  in the package, never made into a remote service.

**Validation gate** — corpus entropy reduction tracked across the v1.7,
v1.8, and v1.9 runs. Calibration check: high-posterior predictions on the
corpus should match observable evidence; intervals should cover the
sparse-evidence cases without collapsing on dense-evidence ones.

### v2.0.0 — Maturity

Lock in what the previous releases proved. Promote stable experimental
fields to the v1.0 schema (or set them as a v2.0 contract); make the
catalog community-PR-friendly; ensure the framework is suitable for
monthly cadence on a large private corpus indefinitely.

- **BIMI VMC legal-name clustering.** Pairs with the hypergraph view from
  v1.8; promote to general availability with a corpus-delta showing real
  multi-brand identification.
- **Schema lock for experimental fields.** Move the v1.7-v1.9 fields that
  proved stable into the v1.0+ schema contract, with the `unclassified_*`
  and Bayesian fields explicitly versioned.
- **MCP delta helper.** Compares supplied or cached JSON only; no hidden
  network. The first first-class delta surface usable by AI agents. An
  optional `include_fusion` flag surfaces v1.9 posterior shifts (slug
  posteriors and credible-interval changes) alongside the deterministic
  diff, so agents can ask "did the probability mass move?" not just "did
  a slug appear or disappear?".
- **Catalog metadata push.** Description coverage > 80%, reference
  coverage > 25%, deliberate non-default weights documented per
  fingerprint. The catalog becomes contributor-grade.
- **Documentation snapshot.** [`correlation.md`](correlation.md) (currently a
  living draft) will be promoted to a polished reference describing the
  full inference pipeline (rules → graph → Bayesian) with worked examples
  and the language hedge each layer applies. Includes a small
  **defense ↔ correlation mapping** table so a defender can read across
  from "what I'm worried about" (e.g. shadow infrastructure, lookalike
  domains, sovereignty drift, supply-chain motif change) to "which
  correlation layer surfaces it" (rules, wildcard SAN siblings, temporal
  bursts, chain motifs, community detection, posterior shift).

**Validation gate** — final corpus run validating end-to-end across all
layers, with the corpus expanded to ≥10k domains where feasible. Trend
metrics across v1.6 → v2.0 demonstrate the correlation engine got better
without overclaiming.

### Backlog (after v2.0)

Items that are real but speculative enough to not commit a slot in the
plan above. Each remains gated by the same invariants and validation
discipline.

- CT organization-name search (opt-in, exact-match only).
- Wayback Machine temporal enrichment (new public network surface; opt-in).
- Deeper hardening simulation UX (high overreach risk).
- Anomaly detection on issuer-mix changes over time.
- Per-domain inference cache for batch-mode reruns.

## Good First Roadmap Items

Narrow, useful, aligned with the product shape. Each one is a single PR
with a corpus-delta or audit note. None of these block a release; they
are picked up alongside the build plan above.

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
