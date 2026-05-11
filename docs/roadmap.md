# Roadmap

This file is forward-looking. Shipped work belongs in
[CHANGELOG.md](../CHANGELOG.md); release mechanics belong in
[release-process.md](release-process.md).

Current release: **v1.9.3.4** (Security: MCP doctor/install path isolation — addresses audit finding *"MCP doctor/install can execute shadowed recon_tool package"* via three defense layers: safe-cwd + `PYTHONSAFEPATH=1` in `mcp_doctor`, persisted `PYTHONSAFEPATH=1` env in install fallback configs, runtime guard in `server.py` that refuses cwd-shadow loads).
Current theme: treat correlation as inference
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

As of v1.8.0, built-in fingerprints live in nine categorized YAML files:
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

## Engineering quality posture

Standing engineering practices — type checking, lint gates, test
coverage, dependency audit, trusted-publisher releases, structured
logging, schema versioning, property-based fuzzing — are the floor
this roadmap assumes. They are documented in `CONTRIBUTING.md` and
exercised by CI; the v1.9.x and v2.0 plans below build on top of
them.

A few patterns are distinctive enough to call out:

- **Strict-positive likelihoods, no degenerate factors.** The
  Bayesian schema rejects `{0, 1}` likelihoods because one
  mis-fingerprint would otherwise pin a node permanently.
- **Cache-poisoning resilience.** Cache loaders skip malformed
  entries instead of crashing.
- **Property-based testing where invariants exist.** Hypothesis
  generates random valid networks and evidence sets to surface
  edge cases unit tests miss.
- **Pure-Python dependency floor.** No numpy, no scipy, no
  probabilistic-programming framework. `pip install recon-tool`
  pulls roughly eight runtime packages.

### Known gaps

The list of things a security-focused project ideally has but we
do not yet ship. Listed publicly so an evaluator can see what we
know is missing rather than only what we know is present:

- ~~No SBOM attached to releases.~~ **Shipped in v1.9.3.1** —
  CycloneDX SBOM (`recon-tool-<version>.cdx.json`) attached to
  every GitHub Release as an artifact, generated by the release
  workflow from the same locked dependency set the audit gate
  validates.
- ~~No SECURITY.md / vulnerability disclosure policy.~~ **Shipped
  pre-v1.9.3.1** — see `SECURITY.md` for scope, response SLA,
  reporting channel, and the MCP-specific threat model.
- ~~No secrets-scanning in CI.~~ **Shipped in v1.9.3.1** —
  gitleaks runs on every PR, every push to main, and on a weekly
  scheduled scan against the historical branch tree. Read-only
  workflow permissions; failures are non-bypassable.
- ~~No forward-compat cache test.~~ **Shipped in v1.9.3.1** —
  `tests/test_cache_forward_compat.py` pins the implicit "ignore
  unknown fields, load known fields cleanly" contract that the
  reader has always honoured but never tested.
- No mutation testing — line coverage measures execution, not
  test quality. Open; tracked for post-v2.0 if line coverage
  starts feeling like a false-positive signal.
- No SLSA provenance or reproducible-build verification.
  Deferred; valuable but disproportionate for a stdio-only tool
  at current scale.

These do not block v1.9.x or v2.0. The four cheap ones
(SECURITY.md, SBOM, secrets-scanning, forward-compat test) all
shipped by v1.9.3.1 — the engineering-quality "what's still
missing" list shrunk meaningfully in one patch. The expensive
ones (SLSA, reproducible builds, mutation testing) wait.

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
- **Per-release calibration aggregate publish.** Each v1.9.x patch
  ships its own one-page validation summary
  (`validation/v1.9.N-calibration.md`) with sensitivity numbers, ECE
  on the synthetic network, and corpus spot-check rate at that point.
  Established for v1.9.0; the practice continues per patch so
  calibration claims are falsifiable across time, not just at the
  v2.0 lock moment.

### v1.7.0 — Hardened-target signal recovery (shipped)

Squeezed more out of CT logs and resolution chains, and surfaced what
we already tracked but didn't expose. Everything in this release landed
as a YAML data file plus minimal engine extension. See
[`CHANGELOG.md`](../CHANGELOG.md) for the full notes.

- **Wildcard SAN sibling expansion.** Implemented in
  `recon_tool/sources/cert_providers.py` `_extract_wildcard_sibling_clusters()`.
  Surfaced under `cert_summary.wildcard_sibling_clusters` in `--json`.
- **Temporal CT issuance bursts.** Implemented in
  `recon_tool/sources/cert_providers.py` `_detect_deployment_bursts()`.
  Surfaced under `cert_summary.deployment_bursts` with relative window
  deltas (no absolute "same owner" claims).
- **CNAME chain motif library.** Catalog at
  `recon_tool/data/motifs.yaml`; loader and matcher at
  `recon_tool/motifs.py`; integrated in
  `recon_tool/sources/dns.py` `_classify_related_surface()`. Surfaced as
  the top-level `chain_motifs` array in `--json`. Chain length capped
  at 4. Per-lookup observation cap at 50.
- **Cross-source evidence conflict surfacing.** Implemented as
  `serialize_conflicts_array()` in `recon_tool/models.py` and the
  top-level `evidence_conflicts` array in `format_tenant_dict()`. The
  legacy `conflicts` dict under `--explain` is unchanged.

### v1.8.0 — Graph correlation (shipped)

Built the structural layer on top of the v1.7 cert intelligence. SAN
co-occurrence becomes communities, fingerprint metadata becomes
ecosystem hyperedges, and absence rules turn vertical profiles into
hedged baseline checks. Zero new network surface. See
[`CHANGELOG.md`](../CHANGELOG.md) for the full notes.

- **CT co-occurrence graph + Louvain communities.** Implemented in
  `recon_tool/infra_graph.py`. Surfaced under top-level
  `infrastructure_clusters` in `--json` (always emitted). 500-node cap
  with connected-components fallback. Louvain via pure-Python
  `networkx` (Leiden's well-connectedness guarantees do not pay off at
  this graph size, and `leidenalg` would pull in C extensions).
- **Fingerprint relationship metadata.** Three optional fields on the
  fingerprint YAML schema (`product_family`, `parent_vendor`,
  `bimi_org`); eight built-in slugs seeded. Surfaced as
  `fingerprint_metadata` map in `--json`.
- **Hypergraph ecosystem view (batch-only).** Implemented in
  `recon_tool/ecosystem.py`. Behind `recon batch --json
  --include-ecosystem`. Four hyperedge types (top_issuer, bimi_org,
  parent_vendor, shared_slugs ≥2). Wraps batch JSON in
  `{ecosystem_hyperedges, domains}`.
- **Vertical-baseline anomaly rules.** `Profile` YAML gains
  `expected_categories` + `expected_motifs`. New
  `compute_baseline_anomalies()` in `recon_tool/profiles.py` emits
  hedged observations on missing expectations; seeded on `fintech` and
  `healthcare` profiles.
- **`get_infrastructure_clusters` + `export_graph` MCP tools.**
  Read-only exposure of the already-computed graph. The first emits
  the cluster envelope; the second emits raw nodes + weighted edges +
  cluster_assignment for downstream Mermaid / GraphViz / CSV pipelines.

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

### Bridge to v2.0 — patch releases, in logical order

v1.9.0 shipped the third correlation layer behind `--fusion` with
EXPERIMENTAL on every new surface. The bridge to v2.0 is a series
of small, focused patch releases — each clearing exactly one
milestone. Patches ship when work completes, not on a fixed
schedule. We are not allergic to many patch releases; we are
allergic to bundled releases that combine unrelated work.

The bridge sequence starts at **v1.9.2**: `v1.9.1` was used for the
optional "conflict provenance on `NodePosterior`" feature (listed
in the v1.9.x optional additions below) before the bridge plan
stabilized. Bridge milestones are numbered in delivery order from
there, so the six patches below cover **v1.9.2 through v1.9.7**.

v2.0 itself is reserved for "polished and excellent everywhere" —
the schema lock, the doc polish, the BIMI VMC promotion. v2.0 is
*not* a place to park feature backlog; if a feature is real and
gated, it ships in a v1.9.x patch and v2.0 inherits it as already-
present.

The milestones below are ordered to put **operator UX signal
first**, so schema-affecting work is informed by what operators
actually use rather than the other way around. Each milestone
maps to one patch release.

#### v1.9.2 — UX validation via agentic QA (shipped)

We have not validated that operators benefit from credible
intervals. The entire calibration argument is academic if no one
looks at the `posterior_observations` block before making a
decision. Doing this first, before any schema-affecting work,
prevents us from locking a contract whose user-facing value is
unproven.

The original framing called for three human operator interviews
(SOC analyst, security architect, due-diligence reviewer). We
keep that as a future option, but the **primary v1.9.2
methodology is agentic QA** — one of recon's main user personas
*is* the AI agent (the entire MCP integration story), so
simulating that persona with a script gives us:

- Real signal about whether agents read `posterior_observations`,
  whether they distinguish dense from sparse, whether they cite
  `--explain-dag` output, whether they ask follow-up questions
  the credible interval should answer.
- Reproducibility: anyone can rerun the agentic QA suite against
  a future build and compare.
- Speed: today, not "after we recruit three humans."
- Publishability: synthetic / fictional domains, no private data.

**Method.**

- **Personas as prompt scaffolds.** Three personas — security
  analyst triaging an alert, due-diligence researcher writing a
  vendor assessment, ops engineer comparing two domains. Each
  gets a system prompt that defines their role, the question
  they're trying to answer, and the artifacts available
  (`recon <domain> --fusion --json`, `--explain-dag`, MCP tool
  output). No mention of credible intervals, sparse flags, or
  evidence DAGs in the prompt — we want to see whether the
  agent finds and uses those affordances on its own.
- **Test domains.** Two fictional Microsoft examples
  (`contoso.com` for dense, a deliberately-hardened scenario
  built by stripping a normal lookup down to one slug for
  sparse). Synthetic, public, reproducible.
- **Scoring rubric.**
  - *Did the agent read the posterior block?* (binary; check
    transcript)
  - *Did the agent cite the credible interval explicitly?*
    (binary)
  - *Did `sparse=true` change the agent's conclusion?*
    (compare answers on dense vs sparse domain)
  - *Did the agent run `--explain-dag` or call
    `explain_dag` MCP?* (binary)
  - *Did the agent reach a different conclusion than it would
    have without `--fusion`?* (re-run with `--fusion` off and
    diff)
- **Documented in `validation/v1.9.2-agentic-ux.md`.** The
  prompts, transcripts, and rubric all public-reproducible.
  Per-persona summary table makes the result skimmable.
- **Failure modes that change v2.0.** If the agent ignores the
  posterior block on both runs, intervals are not load-bearing
  and v2.0 should consider promoting `posterior_observations`
  to stable but de-emphasizing it in the panel. If the agent
  consistently misreads `sparse=true` as "low confidence" rather
  than "passive ceiling," the field name is wrong and v2.0
  should rename. If the agent uses `--explain-dag` heavily,
  v2.0 should keep it prominent. Each finding maps to a concrete
  v2.0 disposition decision.

**Human interviews remain a future option.** If the agentic QA
surfaces ambiguous results, or if we want a non-agent persona
(SOC analyst clicking through the CLI), the original three-
interview plan is on the shelf. But agentic QA is genuine
validation for the agent persona, not a placeholder for it.

#### v1.9.3 — Resolve the `email_security_strong` definitional gap (shipped)

This is *topology surgery*, not parameter tuning. The v1.9.0
spot-check showed 52.6% agreement on this single node; all other
nodes were at 100%. The cause is not miscalibration. The Bayesian
network's CPT for `email_security_strong` is parameterized over
`{m365_tenant, google_workspace_tenant, email_gateway_present}` —
modern-mail-provider presence. The spot-check tested it against
`dmarc=reject + dkim + spf-strict + mta-sts (≥2 of 4)` — policy
enforcement. **These are different claims.** No CPT tuning makes
them agree. Two principled fixes:

- **Option A — Split the node.** Replace `email_security_strong`
  with two nodes: `email_security_modern_provider` (parameterized
  on M365 / GWS as today) and `email_security_policy_enforcing`
  (parameterized on observed DMARC / DKIM / SPF / MTA-STS signals).
  Defenders care about both, but for different reasons. Two nodes
  with two clear definitions beat one with a muddled one.
- **Option B — Pick a definition and align both layers.** Choose
  whichever definition matches the question defenders actually ask
  (likely policy-enforcing), align the deterministic pipeline check
  and the Bayesian CPT to that definition, and live with the choice.

Default: Option A. It's more model surface but more honest. The
implementation is a schema-additive `bayesian_network.yaml`
change, not a CPT tune. **Gate:** both new nodes ship with explicit
definitions in `docs/correlation.md` and a re-run corpus
spot-check matches the definitions.

**Adjacent suspect — `federated_identity`.** The current model
parameterizes federation only on `m365_tenant`, but federation
exists without M365 (Okta + GWS, Auth0 + custom IdP, standalone
SAML setups). The current network systematically under-attributes
federation when the path doesn't go through M365. This is the
same shape of definitional bug as `email_security_strong`. We
either (a) expand `federated_identity`'s parents and re-derive
its CPT, or (b) keep it `experimental` until corpus evidence
shows the under-attribution rate is acceptable. Decide as part
of this milestone.

**Audit-every-node — backlog, not commitment.** The pragmatic
choice is to fix the one we know is broken, ship, and let the
next corpus run tell us which node is broken next. Sequential
model improvement. The rigorous-but-open-ended alternative — audit
every node for definitional clarity in one pass — is in
[Backlog (after v2.0)](#backlog-after-v20) below.

#### v1.9.4 — Hardened-adversarial behavior validation

The v1.9.0 corpus skewed enterprise. The asymmetric-likelihood
design (§4.8.3) was justified specifically for hardened targets,
which v1.9.0 did not exercise. This milestone validates the
*design property*, not just the calibration:

- **50-domain hardened-adversarial subset** under
  `validation/corpus-private/hardened.txt`: minimal-DNS,
  wildcard-cert-only, heavily-proxied apexes, randomized CNAME
  chains, short-lived certs.
- **Gate (behavioral, not numeric):** on this subset, the layer
  must (a) flag `sparse=true` on most nodes, (b) report wide
  credible intervals, and (c) refuse to report high-confidence
  posteriors on nodes whose evidence bindings did not fire. The
  exact numeric thresholds are less important than the
  qualitative behavior holding up. Document the result with
  illustrative interval shapes in correlation.md.
- **Public failure-mode catalog.** New section in correlation.md
  enumerating the hardening patterns that defeat each layer and
  the language the layer uses to admit it ("layer X reports
  sparse on this pattern"). Honest framing of where the public
  channel really cannot resolve uncertainty.

**Quality bar — exceptionally well (every item must be checked):**

- [ ] Hardened corpus has explicit *inclusion criteria* documented
  at the top of `validation/corpus-private/hardened.txt`: a domain
  qualifies iff it satisfies ≥ 3 of {wildcard SAN ratio ≥ 80%,
  CNAME chain depth ≥ 3, no public IdP metadata, ≤ 2 public DNS
  records beyond the apex, certificate validity ≤ 30 days}. Public
  enough that someone else can build a comparable corpus from
  CT-log scans + heuristics.
- [ ] **Full v1.9.0 91-domain corpus re-run** against the v1.9.3
  topology (deferred from `v1.9.3-calibration.md`), reported in
  `validation/v1.9.4-calibration.md` alongside the hardened subset.
  Trend numbers v1.9.0 → v1.9.3 → v1.9.4 published per node.
- [ ] **Per-hardening-pattern result rows** in the failure-mode
  catalog. Not "the layer reports sparse on hardened targets" but
  "wildcard-cert-only targets: cdn_fronting fires (CNAME path),
  every other node sparse, federated_identity interval [0.0, 0.45];
  randomized-chain targets: chain_motifs fires when motif library
  hits, otherwise sparse; etc." One row per hardening pattern.
- [ ] **Survival rate** quantified: what fraction of high-confidence
  posteriors *survive* migration from soft-target corpus to
  hardened-target corpus, per node. The honest number — most should
  vanish; the ones that don't are the leak surfaces.
- [ ] **No new code-path regressions on the soft corpus** —
  re-running the v1.9.0 corpus shows the same 100% per-node
  agreement (other than `email_security_strong` which is gone).
- [ ] **Failure-mode catalog cross-referenced** to specific
  defensive guidance in correlation.md §4.8.8 (Defensive value):
  "if you're worried about X, the correlation layer that surfaces
  it is Y; if X is hardened away, the layer reports Z."
- [ ] **Reproducibility section** in `v1.9.4-calibration.md` shows
  how an outside reader could build a comparable hardened corpus
  from public sources (CT-log queries against short-lived issuers,
  filter for wildcard SANs, etc.). Anonymized aggregates only.

#### v1.9.5 — Per-node stability criteria (decide, don't ship the field)

The current EXPERIMENTAL label is atomic — the whole `--fusion`
layer carries it. That's over-broad. `m365_tenant`, `cdn_fronting`,
`aws_hosting`, `google_workspace_tenant` were validated at 100%
spot-check on the v1.9.0 corpus. `email_security_strong` was not.
They should not share a label.

This patch is about *deciding the criteria*, not shipping a
field. v2.0 ships with no `experimental` labels anywhere
(see v2.0.0 below), so the `stability: stable | experimental |
deprecated` field has nothing to express at v2.0 release time.
Ship the field when it's actually needed — which is the first
time a post-v2.0 patch adds a node that doesn't immediately
qualify as `stable`.

- **Per-node stability criteria** (behavioral, not engine-tautological):
  - **(a) Evidence-response correctness.** The node's posterior
    moves in the predicted direction when relevant evidence is
    added or removed, and *does not* move when irrelevant
    evidence is varied. This validates the network propagation
    works as designed for that node, not just that the engine
    runs Bayes.
  - **(b) Calibration in both regimes.** When the deterministic
    pipeline classifies the slug `high`, the Bayesian posterior
    is also high (> 0.5) and the credible interval does not span
    the full `[0, 1]` range. When the deterministic pipeline is
    silent (sparse target), the interval widens appropriately
    rather than collapsing on a confident-looking point estimate.
    Two binary checks; no ground-truth probability claim.
    Alongside these, record per-node **proper scoring rules**
    (Brier score, log-score) and **expected calibration error
    (ECE)** computed against the deterministic pipeline's
    high-confidence verdicts as a proxy label. These are
    diagnostic, not gating: a node with bad ECE on the proxy is
    flagged for re-examination of its CPT or topology, not
    auto-failed. The point is to make the verdict numerically
    defensible rather than purely behavioral.
  - **(c) Independent-firing threshold.** The node's evidence
    bindings have fired on at least N independent domains in
    aggregate corpus runs. Without enough firings we don't have
    enough data to support promotion regardless of point-spot-
    check rates.
- **Apply the criteria to the v1.9.0 seed network.** Each node
  gets a verdict — `stable` (clears all three) or `not yet`
  (one or more criteria unmet). The `not yet` verdicts feed
  the v2.0 disposition decisions: split the node, redefine it,
  remove it after a deprecation patch, or keep working on it
  in v1.9.x.
- **The `stability` field itself ships in v2.1 or later**, the
  first time a new node is added that needs the `experimental`
  value. v2.0 ships without the field; the schema disposition
  table accounts for nodes by name, not by per-node label.

**Quality bar — exceptionally well:**

- [ ] **Per-node verdict table** in `validation/v1.9.5-stability.md`.
  One row per node, three columns (a / b / c), explicit pass/fail.
  Pass requires *all three* — partial-pass nodes are `not yet`.
- [ ] **Numeric backing for criterion (b)**: per-node Brier score,
  log-score, and ECE on the v1.9.4 corpus run, with ranges
  documented (e.g., "ECE ≤ 0.20 considered acceptable for
  stable; > 0.20 flagged for re-examination, not auto-failed").
- [ ] **Independent-firing threshold (c) explicit**: N ≥ 10
  independent domains for stable; the table records the actual
  firing count per node from the v1.9.4 corpus, not a self-report.
- [ ] **Criterion-(a) test exists in code** as a parametrized
  test (`tests/test_node_stability_criteria.py`) — for every
  node, an assertion that varying its bound evidence moves its
  posterior and that varying unbound evidence does *not*. The
  test failing is a regression signal, not a v1.9.5-only check.
- [ ] **`not yet` verdicts route to specific dispositions** before
  v2.0:
  - Split the node (per v1.9.3 surgery template)
  - Redefine it (CPT changes with concept comments per v1.9.6)
  - Remove it (one-patch deprecation → next-patch deletion;
    no "experimental at v2.0" allowance)
  Each `not yet` node carries its disposition decision in the
  same v1.9.5-stability.md row.
- [ ] **No fast-tracking on numbers alone.** A node with great ECE
  but only 4 firings does not pass — the threshold is *all three*.

#### v1.9.6 — CPT-change discipline (concept, not parameter)

Empirical Bayes — deriving CPT parameters from corpus statistics —
crosses the project's "no learned weights" invariant. We almost
did it: the v1.9.0 validation report initially recommended
"lower `P(strong|M365+gateway)` from 0.75 → ~0.55 because the
corpus shows 55%." That recommendation was wrong, not in the
target number but in the framing.

- **Discipline:** corpus runs are mirrors, not fitters. The
  human's job is to question the *topology* — is this node
  asking the right question? — not to minimize the disagreement
  number. If the disagreement is high, the *first* hypothesis is
  that the model is conceptually wrong (v1.9.3's
  `email_security_strong` story). Only after the topology is
  clean do CPT numbers get re-examined, and only with explicit
  reasoning written in the YAML.
- **Iteration cycle is fine; automation is not.** Iterating
  "look at corpus → rewrite mental model → write new CPTs" with
  a human in the loop is the right way to improve the model. An
  automated pipeline that reads the corpus and emits CPTs
  without questioning the topology crosses the invariant. The
  bright line is whether a *concept* gets reconsidered when the
  numbers disagree.
- **Enforcement.** Add a contributor-facing note in
  `CONTRIBUTING.md` requiring every CPT change to carry a
  comment in the YAML explaining the concept the change
  reflects, not just the corpus statistic that motivated it.
  PR review enforces; no automated test, because the test would
  game the comment requirement without measuring whether the
  concept-questioning actually happened.

**Quality bar — exceptionally well:**

- [ ] **Worked example in CONTRIBUTING.md**: the v1.9.3 surgery
  used as the canonical case. "We almost tuned a CPT and shipped;
  the right answer was topology surgery. Here's how to recognize
  the same pattern." Concrete enough that a future contributor
  facing a similar disagreement asks the topology question first.
- [ ] **PR-template addition**: a non-blocking checkbox `[ ] If
  this PR changes any CPT entry in bayesian_network.yaml, the
  YAML carries a comment explaining the *concept* this change
  reflects, not just the corpus statistic that motivated it.`
  Pre-filled in `.github/pull_request_template.md`. Reviewer
  enforces; checkbox is the prompt.
- [ ] **Anti-pattern catalog**: explicit list of changes the
  reviewer should reject — "lowered P(X|Y) from 0.75 to 0.55 to
  match corpus rate" without a concept comment is the canonical
  rejection. Three or four worked rejections in CONTRIBUTING.md.
- [ ] **No automated CPT-fitting tooling**: confirm no script
  under `scripts/` or `validation/` has emerged that auto-emits
  CPT values from corpus statistics. Periodic audit, not a
  test (the audit is the discipline).

#### v1.9.7 — Metadata-coverage gate (presence, not coverage)

The v1.9.0 advisory gate measures description coverage as a
percentage. Forcing 70% coverage means writing ~190 description
strings, many of which would be one-line placeholders just to
clear the gate. That's gate-gaming.

- **Reframe the metric.** Replace "≥ 70% description coverage on
  identity / security / infrastructure" with "every detection in
  identity / security / infrastructure has a non-empty
  description." Binary per-detection, not percentage per-
  category. Catches *omission*, not richness; richness is for
  PR review.
- **Implementation.** Modify
  `scripts/check_metadata_coverage.py` to count
  detections-with-empty-or-missing-description rather than
  percentage. Flip from advisory to enforcing when the count for
  gated categories is zero.

**Quality bar — exceptionally well:**

- [ ] **Per-category gap report**: when the script fails, output
  lists the exact slug + detection-rule pair missing a
  description, grouped by category. A contributor sees "fix
  these 7 entries" not "your category coverage dropped to 87%."
- [ ] **Pre-commit hook entry** added to `.pre-commit-config.yaml`
  so the gate fires locally before push, not just in CI. Faster
  feedback loop; aligns with the project's existing pre-commit
  posture.
- [ ] **What-good-looks-like guide** in `CONTRIBUTING.md`:
  description rubric requiring (a) what slug detects, (b) what it
  doesn't detect, (c) common false positives if known. Two or
  three worked examples (good vs placeholder). Empty-string
  presence checks the floor; the rubric raises it for new
  contributions.
- [ ] **Backfill before flip**: zero detections in
  identity/security/infrastructure are missing descriptions
  before the gate flips from advisory to enforcing. The flip is
  the last commit of v1.9.7, not the first; the patch ships with
  zero CI breakage on main.
- [ ] **Reference-presence reporting** added (advisory only at
  v1.9.7): script also reports references-missing per-detection
  count, but does not fail. Sets up the Track B metadata richness
  pass that follows.

#### Patch-release discipline

Each v1.9.x patch ships when *that one milestone* is complete.
This is intentional:

- **One milestone per patch** keeps the diff small and the changelog
  honest. A user reading "v1.9.4 — hardened-adversarial validation"
  knows exactly what shipped and what to test.
- **No bundling.** Two milestones completing on the same day is
  fine; they still ship as separate patches with separate tags.
  Bundled releases hide work and make rollback harder.
- **Numeric order IS delivery order.** v1.9.2 ships before
  v1.9.3; v1.9.3 before v1.9.4; and so on. The dependency chain
  is the point of the planning: UX validation (v1.9.2) informs
  topology surgery (v1.9.3), which informs hardened-adversarial
  testing (v1.9.4), which informs the per-node stability
  decisions (v1.9.5), which informs CPT-change discipline
  (v1.9.6), which informs the metadata gate (v1.9.7). Skipping
  ahead because a later patch "feels easier" means we're
  guessing at the dependency we just decided to think about.
- **Bug-fix patches use the next available number.** A regression
  fix that lands between v1.9.5 and v1.9.6 ships as `v1.9.5.1`
  or claims the next minor number — whichever the project's
  versioning strategy prefers at that moment. Bug fixes do not
  block bridge milestones, and bridge milestones do not block
  bug fixes; both make linear progress through their own number
  spaces.

EXPERIMENTAL labels come off per-node as the gates clear, not all
at once. By the time the sixth patch ships, every surface is
either `stable`, explicitly `experimental` (and we know why), or
explicitly `deprecated`.

**v2.0 ships with zero EXPERIMENTAL labels anywhere.** This is a
hard rule, not an aspiration:

- Nodes that have cleared the v1.9.5 stability criteria → ship in
  v2.0 as `stable`.
- Nodes that have not cleared the criteria by v2.0 release time →
  **removed from `bayesian_network.yaml` for v2.0**, not shipped
  as `experimental`. They can be re-added in a v2.x patch once
  the corpus exposure validates them. A removed-and-re-added node
  is honest; an "experimental at v2.0" node is not, because v2.0
  is supposed to be the polished release.
- The per-node `stability` field stays in the schema for *future*
  use (post-v2.0 additions ship as `experimental` and graduate
  to `stable` later). It is not a v2.0 label-leftover surface.

This is stricter than the previous draft. The previous draft
allowed `experimental` per-node at v2.0; we removed that
allowance. If a node can't earn `stable`, it doesn't belong in
v2.0, full stop.

### v1.9.x — Required quality work for v2.0 (parallel to the bridge milestones)

The six bridge milestones above resolve known *correctness* gaps in
the Bayesian layer. The items below resolve known *quality* gaps —
explainability, supply-chain hygiene, and consumption ergonomics —
that v2.0 cannot honestly ship without. They are not bridge
milestones (no dependency chain among them; they can land in any
order under whatever v1.9.x.y patch numbers are available), but
they are *required* before v2.0 in the same sense the bridge
milestones are.

The reason these moved from "optional" to "required": v2.0 is the
"polished and excellent everywhere" release. Calling these optional
while the roadmap simultaneously cites their gaps (187/485 detections
have descriptions; "Known gaps" lists missing SECURITY.md, SBOM,
secrets-scanning) is internally inconsistent. Either the gaps are
real and need closing for the polished release, or they are not real
and don't belong on the gap list. They are real.

- **Catalog metadata richness pass.** Beyond the v1.9.7 presence
  gate, raise description coverage to ≥ 80%, reference coverage to
  ≥ 25%, document deliberate non-default weights per fingerprint.
  Pure data work, no schema change. **Required because** the tool's
  value prop is auditable, debuggable evidence; shipping a v2.0
  whose `--explain` panel surfaces slugs without descriptions or
  reference links is an explainability gap that the priority order
  (correctness → reliability → **explainability** → composability)
  promises to close before v2.0.

  **Quality bar — exceptionally well:**
  - [ ] Description rubric (in `CONTRIBUTING.md`): each detection's
    description states (a) what the slug detects, (b) the
    observable signal pattern, (c) common false-positive
    configurations if known. One sentence each; not boilerplate.
  - [ ] References point to *vendor-published* DNS / MX / CNAME /
    TXT documentation when possible (auditable third-party source),
    not blog posts. Where vendor docs are absent, link to the
    relevant RFC or to a stable archived URL.
  - [ ] Audit pass: every existing description re-read against the
    rubric, not just gap-filling. Placeholder descriptions ("Detects
    Foo") flagged and rewritten. The pass is a single multi-PR
    workstream tracked in `validation/metadata-audit.md`.
  - [ ] Chunked into PRs of ≤ 30 fingerprints each; each PR
    independently reviewable; no single mega-PR.
  - [ ] Coverage check script reports both presence (v1.9.7 gate)
    and *richness signals* (mean description length, reference
    presence, non-default weight rationale). Richness numbers are
    advisory; presence stays enforcing.

- **SECURITY.md and supply-chain hardening.** *(shipped in v1.9.3.1)*
  Explicit vulnerability-disclosure policy, gitleaks
  secrets-scanning in CI, SBOM (CycloneDX) attached as a release
  asset, forward-compat cache-loading test. **Required because**
  the project's own "Known gaps" section called these out as
  "things a security-focused project ideally has but we do not yet
  ship." A polished v2.0 of a defensive security tool cannot leave
  that list intact. See v1.9.3.1 CHANGELOG entry for the full
  per-item quality-bar verification.

- **Downstream consumption examples** (at least two SIEMs).
  Copy-pasteable parsers / field mappings for at least Splunk and
  one of (Elastic / Sentinel / ArcSight). recon's `--json` /
  `--ndjson` shape is already the integration surface; these turn
  the schema lock from a contract-on-paper into a contract anyone
  can actually consume. **Required because** v2.0 IS the schema
  lock; locking a contract no published example demonstrates is
  premature. Two SIEMs is the floor; more is welcome.

  **Quality bar — exceptionally well:**
  - [ ] Field-by-field mapping table per SIEM: recon JSON path →
    SIEM field → notes. Covers both deterministic-pipeline fields
    (slugs, services, dmarc_policy, etc.) AND fusion-layer fields
    (posterior_observations, evidence_conflicts).
  - [ ] Worked end-to-end example per SIEM: input recon JSON
    (using a Microsoft fictional brand — Contoso/Northwind/
    Fabrikam) → expected SIEM event with severity mapping and
    correlation hints. Both the input and expected output checked
    into `examples/siem/<vendor>/`.
  - [ ] Use-case framing per SIEM: "if you want to alert on
    shadow-IT detection, this is the field path; if you want to
    track DMARC drift over time, this is the schema." Not a
    parser dump; a decision tree for the SIEM operator.
  - [ ] CI test that re-parses the worked-example output and
    diffs against expected, so a v2.0 schema regression breaks
    the SIEM examples (which is the point of having examples
    that validate the contract).
  - [ ] Each SIEM example author-of-record listed; if a vendor
    employee can't QA it, the example is marked
    "community-contributed, unverified."

- **Top-3 influential edges in `--explain-dag`.** *(shipped in v1.9.3.2)*
  Extends `render_dag_text` and `render_dag_dot` to rank fired
  evidence bindings per node by absolute log-likelihood-ratio
  contribution. **Required because** `--explain-dag` is the
  explainability surface v2.0 is supposed to lock; without
  influential-edge surfacing, the layer reports a posterior and
  an evidence list but does not show *which* evidence drove the
  answer. Schema-additive `evidence_ranked: tuple[NodeEvidence, ...]`
  field on `PosteriorObservation` carries the ranking through the
  JSON output, the cache, and the renderer. See v1.9.3.2 CHANGELOG
  entry and `tests/test_explain_dag_top3.py` for the full
  per-criterion verification.

These ship as completed in any order before v2.0; v2.0 inherits them
already-present.

### v1.9.x — Optional feature additions (post-v2.0-friendly)

The features below are *additive* — real new surfaces that don't
require the schema lock and don't gate v2.0. Each ships as its own
patch release with EXPERIMENTAL on its surfaces, can land in any
order, and gets a row in the v2.0 schema-lock disposition table only
if it shipped before the lock; otherwise it inherits a v2.x slot.

- **BIMI VMC legal-name clustering** — pairs with the v1.8
  hypergraph view; demonstrates real multi-brand identification
  on a private corpus.
- **MCP delta helper** — `recon_delta(domain_or_json_a,
  domain_or_json_b)` MCP tool. Compares supplied or cached JSON
  only; no hidden network. Optional `include_fusion` flag
  surfaces v1.9 posterior shifts alongside the deterministic
  diff. The first first-class delta surface for agents.
- **Portfolio / self-audit batch mode** — `recon batch
  --self-audit` aggregating vertical-baseline hits, anomaly
  rules, correlation-depth distribution, and gateway / sovereignty
  consistency across many domains in one summary. Targeted at
  security teams running internal reviews against their own apex
  inventory; never used to score third-party orgs.
- **Non-MCP graph exports** — Mermaid diagram output for the v1.8
  cluster graph, plus CSV exports for relationship metadata and
  chain motifs. Trivial once the graph layer exists; gives
  non-AI users a usable artifact for tickets, decks, audit
  packets.
- **Per-node `n_eff_multiplier` in `bayesian_network.yaml`** —
  schema-additive field that scales effective sample size on a
  per-node basis. Lets weak-calibration nodes (`aws_hosting` and
  any v1.9.5 not-yet nodes that survive into v1.9.5+) widen their
  credible intervals without globally widening every node. Default
  1.0; ≤ 1.0 widens. Replaces the current uniform formula with
  `n_eff = max(_MIN_N_EFF, multiplier * (evidence_count -
  conflict_penalty))`. **Conditionally required** if v1.9.4
  hardened-adversarial findings + the existing sensitivity test
  surface nodes whose interval shape only makes sense with per-node
  scaling; otherwise post-v2.0.
- **Corpus-driven Hypothesis tests** — extend
  `tests/test_bayesian_hypothesis.py` with property tests over
  real corpus output: e.g., "for any domain with ≥ 3 evidence
  pieces and 0 conflicts, interval width ≤ 0.25." Strengthens
  the test floor against future regressions; the existing
  synthetic-network properties already pass.
- **Hawkes-kernel CT burst classification.**
  `_detect_deployment_bursts()` currently uses raw inter-arrival
  deltas. Fit a one-parameter exponential-decay kernel (pure
  Python, no scipy) to each cluster's CT timestamps and
  classify the cluster as `automated_renewal` (short kernel,
  regular cadence — typical of ACME cron jobs) vs.
  `manual_deployment` (longer kernel, irregular bursts — typical
  of operator-driven rollouts). Surface as
  `cert_summary.deployment_bursts[].kernel_class` in `--json`.
  Falsifiable defensive value: the two classes mean different
  things to a defender, and the current uniform "burst" label
  hides that distinction.
- **Asynchronous Label Propagation fallback for `infra_graph`.**
  Pure-Python LPA (near-linear in `|E|`) replaces the current
  connected-components fallback above the 500-node Louvain cap.
  Keeps community structure visible on 10k+ -node graphs without
  importing C extensions. The 500-node Louvain path stays for
  small graphs (modularity is still the better objective there);
  LPA is the honest fallback above the cap rather than the
  flatter connected-components view.
- **Explicit ignorance mass (epistemic vs aleatoric).** Today,
  hardened-target output expresses uncertainty as a wider
  credible interval. A wide interval and "the channel reveals
  nothing here" are not the same epistemic state, and conflating
  them can mislead an agent reading the JSON. Add an optional
  `ignorance` field to `posterior_observations[]` (Dempster-
  Shafer-style mass on the "don't know" state) computed from the
  ratio of unbound to bound evidence nodes for that posterior.
  Surfaces in `--explain-dag` as a third quantity alongside
  posterior and interval. Lets agents distinguish "the model has
  evidence and is unsure" from "the model has no evidence." This
  is the lightweight version of the
  [imprecise-Dirichlet-model backlog item](#backlog-after-v20);
  ship the user-facing distinction first, the deeper credal-set
  refactor only if v2.0+ corpus runs show it pays off.
- **Conflict provenance on `NodePosterior`.** *(shipped in v1.9.1)*
  Today the conflict count feeds the n_eff penalty but the
  *which sources disagreed* detail is dropped. Carry the
  source-pair list and per-pair magnitude through to
  `--explain-dag` and the JSON output, alongside the existing
  top-level `evidence_conflicts` array. Small surface, no
  schema lock implications.
- **Noisy-OR / noisy-AND CPT gates (schema-additive).** Add an
  optional `gate: noisy_or | noisy_and | custom` field on
  multi-parent CPTs in `bayesian_network.yaml`. Default `custom`
  preserves the current explicit dict. Noisy-OR/AND keeps
  multi-parent CPTs compact and human-reviewable as the network
  grows beyond ~10 nodes; matches the positive-only evidence
  bias the asymmetric-likelihood design already commits to. No
  inference-engine change required — the gate compiles to the
  same factor table at load time.

These ship as completed; v2.0 inherits them already-present and
locks their shapes per the disposition table.

### v2.0.0 — Maturity

Lock in what the previous releases proved. Promote stable experimental
fields to the v2.0 schema contract; make the catalog community-PR-
friendly; ensure the framework is suitable for sustained corpus-driven
operation.

**Pre-conditions** — two tracks must clear, both required:

*Track A — Bridge milestones (numeric order; dependency-driven):*

1. v1.9.2 — Operator UX validation via agentic QA documented in
   `validation/v1.9.2-agentic-ux.md`.
2. v1.9.3 — `email_security_strong` definitional gap resolved.
3. v1.9.4 — Hardened-adversarial behavior validated.
4. v1.9.5 — Per-node `stability` field shipped and exercised.
5. v1.9.6 — CPT-change discipline documented in `CONTRIBUTING.md`
   and enforced in review.
6. v1.9.7 — Metadata gate flipped from advisory to presence-
   enforcing.

*Track B — Required quality work (any order, parallel to Track A):*

7. Catalog metadata richness pass — descriptions ≥ 80%, references
   ≥ 25% across the catalog.
8. ~~SECURITY.md and supply-chain hardening~~ — **shipped in v1.9.3.1**
   (vulnerability-disclosure policy, gitleaks secrets-scanning in
   CI, CycloneDX SBOM attached as a release asset, forward-compat
   cache test).
9. Downstream consumption examples — at least Splunk + one of
   (Elastic / Sentinel / ArcSight).
10. ~~Top-3 influential edges in `--explain-dag` rendering.~~
    **Shipped in v1.9.3.2** — LLR-per-binding + percentage influence
    surfaced inline in text + DOT output; schema-additive
    `evidence_ranked` field on `PosteriorObservation`.

Track A patches ship in numeric order. Track B items can land in
any order under whatever v1.9.x.y patch numbers are available.
v2.0 ships when the remaining eight pre-conditions clear (two
already cleared in v1.9.3.1 + v1.9.3.2).

**Schema-lock disposition** (every EXPERIMENTAL field gets a verdict):

| Field | Disposition |
|---|---|
| `posterior_observations` | Promote to stable. Pin `name`, `description`, `posterior`, `interval_low`, `interval_high`, `evidence_used`, `n_eff`, `sparse`. |
| `slug_confidences` | Promote to stable. Existing `[slug, posterior]` shape. |
| `chain_motifs` (v1.7) | Promote to stable if v1.9.x corpus runs continue to fire on real targets. |
| `wildcard_sibling_clusters` (v1.7) | Promote to stable. |
| `deployment_bursts` (v1.7) | Promote to stable. |
| `infrastructure_clusters` (v1.8) | Promote to stable. |
| `ecosystem_hyperedges` (v1.8, batch-only) | Promote to stable; document as batch-only contract. |
| `evidence_conflicts` (v1.7) | Already stable shape; formally promote in schema. |
| `--fusion` flag | Drop EXPERIMENTAL label. |
| `--explain-dag` flag | Drop EXPERIMENTAL label. |
| MCP `get_posteriors` / `explain_dag` tools | Drop EXPERIMENTAL label. |
| `bayesian_network.yaml` topology | Lock at v2.0; further changes require schema-version bump. |
| Bayesian-network nodes that clear v1.9.5 criteria | Ship in v2.0. |
| Bayesian-network nodes that do NOT clear v1.9.5 criteria | Remove via deprecation: a v1.9.x patch marks the node deprecated in CHANGELOG and emits a one-time stderr warning when it's used; the next patch removes it from `bayesian_network.yaml`. v2.0 ships without the node. **No node goes from `experimental` directly to "removed" without a deprecated stop in between.** |
| Per-node `stability` field | Not shipped at v2.0. Reserved for v2.1+ when a new node first needs the `experimental` value. |

**v2.0 itself is purely the lock-and-polish ceremony — two items:**

- **Schema lock.** Apply the disposition table above. Bump
  `docs/recon-schema.json` to v2.0; remove EXPERIMENTAL language
  from the promoted fields' descriptions. This is mechanical
  once the v1.9.x patches have validated everything.
- **Documentation snapshot.** [`correlation.md`](correlation.md)
  (currently a living draft) promoted to a polished reference.
  Sections required for the snapshot:
  - **Defense ↔ correlation mapping** table so a defender can
    read across from "what I'm worried about" (shadow
    infrastructure, lookalike domains, sovereignty drift,
    supply-chain motif change) to "which correlation layer
    surfaces it" (rules, wildcard SAN siblings, temporal bursts,
    chain motifs, community detection, posterior shift).
  - **Prior-art comparison.** Existing probabilistic libraries
    (pgmpy, pomegranate, PyMC / Stan / Pyro) — what they are,
    what they do well, and the specific reasons we did not
    import them. Concepts we adopted are already cited inline
    (Jeffrey 1965, Walley 1991, Augustin et al. 2014, Taroni
    et al. 2014, Minka 2001, Naeini et al. 2015, Pearl 1988,
    Russell-Norvig, Zhang & Poole 1994, Koller & Friedman 2009,
    Blondel et al. 2008, Traag et al. 2019); this section makes
    the *implementation choices* explicit so a PhD reader sees
    what we considered and rejected, not just what we used.
  - **Dependency-floor manifesto.** Complete runtime dependency
    graph (httpx, dnspython, pyyaml, typer, rich, mcp, networkx,
    pydantic-via-mcp) and the list of widely-used libraries we
    *deliberately do not* depend on (numpy, scipy, pandas,
    pgmpy, pomegranate, PyMC, Stan, Pyro, scikit-learn, Redis,
    SQLite, Celery, FastAPI, Shodan / Censys / SecurityTrails
    APIs, GeoIP / ASN databases) with one-sentence reasons.
    Defensive, adaptive, and coding-discipline posture as one
    artifact.
  - **Failure-mode catalog** carried forward from v1.9.4 with
    additional examples accumulated from corpus runs.
  - **Engineering quality posture** carried forward from this
    roadmap, edited for the polished-doc voice.

That is v2.0. Everything else — feature additions, MCP tools,
exports — ships in v1.9.x patch releases as work completes,
under the same EXPERIMENTAL labelling discipline. By the time the
schema lock runs, the features are already in the wild and their
shapes are known.

**Validation gate for v2.0** — re-run the full corpus with the
locked schema; confirm no field-shape regressions. Trend metrics
across v1.6 → v2.0 demonstrate the correlation engine got better
without overclaiming.

**Quality bar for v2.0 itself — exceptionally well:**

- [ ] **Schema lock validates against published consumers.** The
  Track B SIEM examples re-parse without modification on the v2.0
  schema. If a SIEM example breaks, the schema-lock decision was
  wrong (or the example was) — fix one of them before tagging.
- [ ] **`validation/v2.0-validation-summary.md` published** —
  full corpus results, trend table v1.6 → v1.7 → v1.8 → v1.9.0 →
  v1.9.3 → v1.9.4 → v2.0 per node. The trend table is the public
  evidence the engine got better.
- [ ] **All ten Track A + Track B pre-conditions ticked off** in
  the v2.0 release CHANGELOG entry, each with a link to its
  shipping patch. A reader can verify each gate cleared without
  trusting the maintainer's word.
- [ ] **Zero EXPERIMENTAL labels** in any docstring, panel string,
  CLI help text, MCP tool description, or schema field
  description. `grep -ri experimental recon_tool/` returns zero
  user-facing hits (internal test markers excepted). Verified by
  a CI grep gate in `release.yml`.
- [ ] **No "v1.9.x" references** linger in user-facing docs as
  forward-looking commitments. A reader landing on the v2.0 docs
  doesn't see "this will be fixed in v1.9.x"; the items either
  shipped (referenced in past tense) or moved to post-v2.0
  backlog with explicit motivation.
- [ ] **Polish-doc cross-checks** in correlation.md: every cited
  prior-art reference is reachable (no dead links); every
  dependency in the manifesto matches `pyproject.toml`'s actual
  dependency list (no manifesto/code drift).
- [ ] **`recon doctor` updated** to print "v2.0 stable schema" in
  its first line, and to verify the locked schema fields are all
  present in a sample lookup output. The user installing v2.0 sees
  the polish, not just the version number.

### v2.1.0 — Closed-loop fingerprint mining + validation runner (sketch)

The first slot after v2.0 lock. Composability is next in priority
order (correctness → reliability → explainability → composability →
features), and v2.0 doesn't advance it — v2.0 is pure
lock-and-polish on what already works.

The mining primitive already ships. The MCP tool
`discover_fingerprint_candidates(domain)` (live in `server.py`
since v1.7) already does the hard work: resolves the domain,
captures unclassified CNAME chains, applies intra-org / already-
covered filters via `recon_tool/discovery.py::find_candidates`,
and returns a ranked candidate list. The
`/recon-fingerprint-triage` Claude Code skill is already designed
to turn that list into YAML stanzas for `surface.yaml`.

What's missing is *the loop*: a reproducible runner that uses
the existing MCP composition (`lookup_tenant` →
`chain_lookup` → `discover_fingerprint_candidates` →
`test_hypothesis` → `get_posteriors`) to systematically expand
the catalog while measuring whether the expansion actually
tightens correlation depth on the corpus. This makes the "art of
correlation" *executable at scale* instead of a one-time
hand-tuning exercise.

**Primary v2.1 surface:**

- **One new MCP skill:**
  - `run_fingerprint_mining(seed_domains, max_candidates_per_domain=20,
    dry_run=True)` — for each seed, runs the existing chain →
    discovery → hypothesis-test pipeline and draws candidates
    from three already-shipped graph layers: chain motifs (v1.7
    `motifs.yaml` + `discover_fingerprint_candidates`), Louvain
    communities (v1.8 `infrastructure_clusters`), and ecosystem
    hyperedges (v1.8 batch hypergraph). Outputs ranked candidates
    plus the projected impact on the corpus (Δ correlation depth,
    Δ entropy reduction, conflict rate against existing nodes if
    the candidate were accepted). Never writes to committed
    catalogs. `dry_run=True` is the only supported value at v2.1
    ship.
- **One CLI command:**
  - `recon run fingerprint-mining --seed=<domain> --iterations=N
    --dry-run` (alias `recon mine`). Uses the MCP client
    internally so agent and CLI behavior stay identical.
  - Default output is one-line-per-candidate ranked summary
    (rank, candidate suffix, count, projected Δ-correlation-
    depth). `--detail` flag surfaces the full per-candidate
    impact analysis; `--detail --json` emits the structured
    NDJSON for agent consumption. Avoids drowning the operator
    in metrics by default while keeping them one flag away.

**Projection method.** The Δ-metric claims are *empirical*, not
closed-form. For each candidate, the runner constructs a
hypothetical fingerprint (the candidate stanza), uses the
existing `test_hypothesis` MCP path to ephemerally inject it,
re-runs inference on the corpus snapshot, and diffs against the
baseline. No new math, no learned weights — just inference
re-runs over a hypothetical catalog. Falsifiable: if the
operator accepts the candidate and re-runs the full corpus, the
realized delta should match the projected delta to within a
documented tolerance.

**Candidate schema (machine-readable).** Each candidate emitted
by the runner is a dict with these fields:

  - `pattern` (str) — the suffix or substring to match.
  - `tier` (`"application" | "infrastructure"`) — attribution
    precedence layer.
  - `suggested_slug` (str) — slug-shaped identifier proposed for
    the new fingerprint.
  - `count` (int) — how many distinct domains in the corpus
    showed this pattern.
  - `samples` (list of `{subdomain, terminal}`) — up to five
    representative chains for human review.
  - `projected_delta` (dict) — `{correlation_depth, entropy_reduction,
    conflict_rate}` from the empirical re-run.
  - `clue_source` (`"chain_motif" | "graph_community" | "hyperedge"`)
    — which already-shipped layer surfaced the candidate. Lets
    PR review trace each candidate back to a specific motif
    match, Louvain community ID, or hyperedge type rather than
    treating the runner as a black box. Carry the source ID in
    the YAML triage stanza so the provenance chain stays intact
    after merge.
  - `triage_yaml` (str) — pre-formatted YAML stanza ready for
    pasting into `recon_tool/data/fingerprints/surface.yaml`
    pending human review.

**Output contract.** Every run emits NDJSON to
`validation/runs-private/<stamp>/mining/` with three
artifacts: ranked candidates (per the schema above), projected
corpus-level metric deltas, and a triage-ready YAML diff that a
human can review and apply (or reject) by hand.

**Secondary v2.1 surface (only if the primary proves out):**

- `run_validation_suite(domains, metrics=[...])` — packages the
  existing corpus metrics into a reproducible call.
- `batch_posterior_query(domains, nodes=[...])` — parallel
  `get_posteriors` with aggregated stats.

These are wrappers over capabilities the MCP server already
ships. They land only after v2.1 mining itself ships and proves
useful — not preemptively.

**Invariants this preserves:**

- 100% passive — runner only calls existing public-signal tools.
- Data-file only — discovered candidates land in a review queue,
  never in a committed catalog. **`run_fingerprint_mining` ships
  with `dry_run=True` as the only supported value in v2.1.** Any
  future "auto-apply" mode requires its own invariant review and
  a separate release.
- No ML, no autonomous LLM agent inside recon. The "agent" in
  this design is the operator running the CLI or an MCP client;
  the runner is a deterministic coordinator over tools that
  already ship. If we ever want LLM-driven discovery, that's a
  separate invariant decision.
- No active probes, no internet crawling beyond what the
  underlying tools already do.

**Failure modes to avoid:**

- Letting the runner auto-edit `recon_tool/data/fingerprints/`.
  The whole auditability story collapses if recon edits its own
  rules in the dark. Human triage is non-negotiable.
- Calling it "agentic self-improvement" in marketing. We did not
  build a self-improving model; we built a *coordinator over
  existing skills* that helps a human curator move faster. The
  framing matters because it sets the right expectations.
- Adding fifteen new MCP skills as part of v2.1. The cap is one
  primary skill (`run_fingerprint_mining`) plus at most two
  secondaries that are wrappers, not new capabilities. Anything
  more is scope creep and breaks the v2.0 schema-lock contract
  we just wrote.
- Shipping before v2.0 schema lock + v1.9.2 agentic QA prove
  agents use the existing posteriors. v2.1 optimizes a surface;
  if the surface isn't useful, optimization is wasted.

**Why this is the right v2.1 move:**

- v2.1 is **the first release where recon's value compounds with
  use.** Every corpus run produces candidates; every accepted
  candidate increases correlation depth on the next run. The tool
  gets better the more it is used. v1.7 through v2.0 ship a
  static engine; v2.1 is where the engine starts learning from
  its own corpus exposure (with humans-in-the-loop, not
  autonomous fitting).
- It directly advances the north-star metric (multi-signal
  correlation depth) without new math, new network code, or new
  fingerprint surfaces.
- It uses what's already shipped — `discover_fingerprint_candidates`,
  `chain_lookup`, `test_hypothesis`, `get_posteriors` — and
  packages them into a feedback loop that measures its own
  impact.
- It is the natural composability move the priority order
  predicts after explainability is locked.
- It does not require v2.0 to be re-opened. It is purely
  additive on top of the locked v2.0 schema.

**v2.2 escalation path (sketch only).** Pure-`dry_run` removes
auto-edit risk but creates friction: every accepted candidate has
to be hand-pasted from the runner's YAML diff into the catalog.
Tedious tasks don't get done. v2.2 considers a
`--propose-pr` mode that opens a draft GitHub PR with the
candidate stanza added, requires human merge, and never auto-
merges. The audit trail moves from local YAML diff → reviewable
PR. Auto-merge is *never* shipped — that line is permanent. We
articulate the v2.2 path here so the v2.1 friction has a known
answer rather than an open question.

This sketch is **not committed.** The actual v2.1 plan gets
written after v2.0 ships and the agentic-QA findings from v1.9.2
inform whether the mining loop is what operators actually want or
whether some other composability primitive is more valuable.

### Backlog (after v2.0)

Items that are real but speculative enough to not commit a slot in the
plan above. Each remains gated by the same invariants and validation
discipline.

- CT organization-name search (opt-in, exact-match only).
- Wayback Machine temporal enrichment (new public network surface; opt-in).
- Deeper hardening simulation UX (high overreach risk).
- Anomaly detection on issuer-mix changes over time.
- Per-domain inference cache for batch-mode reruns.
- **`--mine-motifs` mode for `run_fingerprint_mining` (v2.2+).**
  Specialised runner mode that proposes new entries for
  `motifs.yaml` (or a sibling `community_motifs.yaml`) by
  clustering recurring chain patterns inside Louvain communities.
  Output includes representative samples and projected
  multi-signal depth gain on the corpus. Same dry-run + human-
  triage discipline as v2.1 mining; never auto-edits the catalog.
  Worth doing only if v2.1 corpus runs show that
  community-scoped motif candidates consistently outscore single-
  domain motif candidates on the north-star metric. The feature
  is additive on top of v2.1's `clue_source: "graph_community"`
  branch and reuses the same projection pipeline.
- **Imprecise Dirichlet Model (Walley 1991) for CPT entries.**
  Replace point-CPT values with intervals derived from
  bounded-prior Dirichlet samples. Yields second-order
  uncertainty on the parameters themselves rather than only on
  the posterior. Major refactor of `bayesian.py`'s factor
  representation; only worth it if v2.0+ corpus runs show the
  fixed-CPT model is the bottleneck. The lightweight v1.9.x
  optional ("explicit ignorance mass") ships the user-facing
  epistemic-vs-aleatoric distinction first; this entry is the
  deeper refactor that would replace point-CPTs entirely once
  the lightweight version proves operators actually consume the
  ignorance signal. Cited in `correlation.md` as prior art.
- **Operator-tuned likelihoods as committed data files.** Allow
  operators to supply per-node likelihood overrides via
  `~/.recon/likelihoods.yaml` analogous to the existing priors
  override. Crosses into v1.9.6's "no automated CPT fitting"
  invariant only if a script auto-derives the file; manual
  operator-side tuning with explicit reasoning is fine. Decide
  the discipline before shipping.
- **Cross-vertical generalization study.** The v1.9.0 corpus
  skews enterprise. A future calibration pass on
  consumer-facing / niche-SaaS targets would tell us whether the
  network's prior assumptions transfer; ECE on that subset is
  the metric.

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

**Statistical methods we deliberately don't use.** External reviews regularly
propose techniques that would cross the invariants. Listed once here so
contributors can see what's off-limits and why, without re-litigating each
proposal:

- *Parameter learning from corpus statistics* (EM, Snorkel, weak-supervision,
  empirical-Bayes auto-fitting of CPTs). Crosses "no learned weights." Corpus
  runs are mirrors that question topology, not fitters that minimize
  disagreement. See v1.9.6 for the discipline.
- *ML structure learning that auto-applies* (PC algorithm or FCI run as part
  of a build pipeline). Constraint-based causal-discovery output as an
  *operator-facing proposal tool* — a human reads the candidate edges and
  decides whether to add them to YAML — is acceptable; the auto-apply step
  is what crosses the invariant.
- *Cross-organization hierarchical models that share evidence between domains
  the operator did not look up together.* Crosses "no aggregate local
  intelligence database." Within-batch sharing (e.g. v1.8 ecosystem
  hypergraph) is fine because the operator chose the batch; persistent
  cross-run state is not.
- *Bundled scientific-Python stack* (numpy, scipy, pandas, scikit-learn,
  pgmpy, pomegranate, PyMC, Stan, Pyro). Crosses the pure-Python dependency
  floor. Pure-Python implementations of specific techniques are fine when
  the technique is genuinely worth it (e.g. LPA, Hawkes-kernel fitting via
  closed-form MLE).
- *Loopy belief propagation, MCMC, particle filtering as the default
  inference engine.* Variable elimination is exact and fast at current
  network size; the ~20-25-node ceiling is a known scaling boundary, not a
  bug. Approximate inference imports complexity that current scale doesn't
  justify.
- *Tractable-circuit compilation* (SPNs, arithmetic circuits) as a v1.x
  upgrade. Real technique, real scaling story — but solves a problem we
  don't yet have. Noted as a known option for post-v2.0 if the CPT space
  grows past what VE handles.
- *Replacing rule-based signals with a single unified PGM.* Misreads the
  layering: slugs are the evidence layer, the Bayesian network is the
  inference layer, signals are the *presentation* layer (operator-facing
  views over slug evidence). Each abstraction is intentionally addressable
  on its own — collapsing them into one model would lose the audit surface
  the project's defensive posture depends on. See
  [correlation.md § Vocabulary](correlation.md#vocabulary).

**Not this tool:** company research, firmographic enrichment, news/funding
feeds, hiring signals, GTM briefings, contact data, maturity scores, HTML
dashboards, TUI, REPL, daemon mode, scheduled monitoring, STIX/Maltego/MISP
exports, Prometheus metrics, Docker image, Homebrew tap, PDF reports.

**Distribution we don't ship:** static binaries (PyInstaller / shiv /
PEX), self-contained installers, OS-native packages (.deb / .rpm /
MSI), Homebrew tap. recon ships as a Python wheel on PyPI; that's
the contract. Static-binary distribution adds signing,
notarization, per-OS verification, and reproducible-build
overhead disproportionate to the audience size. Operators who
need a containerised recon can run it under `uv run` or any
ephemeral Python sandbox; we do not gain from owning that
distribution surface.

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
