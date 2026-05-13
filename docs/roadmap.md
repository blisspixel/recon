# Roadmap

This file is forward-looking. Shipped work belongs in
[CHANGELOG.md](../CHANGELOG.md); release mechanics belong in
[release-process.md](release-process.md).

Current release: **v1.9.4** (hardened-adversarial validation: 50-domain stratified corpus across 5 hardening postures, 100% spot-check agreement, 64.4% sparse-flag rate, asymmetric-likelihood design property validated; failure-mode catalog added to `correlation.md` §4.8.10; A/AAAA internal-DNS leak fixed in CNAME chain walker; Splunk SPL switched from regex to literal set-membership).
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

Built-in fingerprints live in nine categorized YAML files under
`recon_tool/data/fingerprints/`: `ai.yaml`, `crm-marketing.yaml`,
`data-analytics.yaml`, `email.yaml`, `infrastructure.yaml`,
`productivity.yaml`, `security.yaml`, `surface.yaml`
(per-subdomain CNAME-target classification, added in v1.5), and
`verticals.yaml`.

**Current totals** *(as of v1.9.3.9)*:

- 414 fingerprint entries; 343 unique slugs.
- All slugs map to a defender-visible category in `formatter.py`.
- Zero cross-file slug-name collisions (verified by `tests/test_fingerprint_expansion.py`).

**Coverage outlook.** v1.9.3.9 closed the largest cloud-vendor coverage
blindspot (GCP / Azure non-O365 / Oracle / IBM / Alibaba / SaaS-PaaS /
SSE-SASE) via vendor-doc-sourced fingerprints. Empirical validation
against a stratified sample of known-rich-stack public companies
(Stripe, Shopify, Slack, Atlassian, Datadog, HashiCorp; gitignored
private corpus) showed **zero unclassified CNAME chain termini** on
these targets — the catalog is comprehensive for top-tier enterprise
vendors. Residual coverage gaps live in lesser-known regional clouds
(Yandex, OVH, Kakao), SAP / Oracle SaaS apps beyond Fusion, and the
long-tail SSE/SASE vendors (iboss, Versa, Aryaka).

**What remains.** The metadata richness pass is the largest pending
catalog-quality item — see Track B below. Description and reference
coverage targets (≥ 80% / ≥ 25%) before v2.0; the vendor-doc-sourced
methodology codified in `CONTRIBUTING.md` advances reference coverage
on every new `cname_target` rule shipped under it.

**Detection-gap honesty.** Coverage is bounded by passive DNS
fundamentally: server-side API consumption, internal workloads, data
pipelines, and ML jobs that call cloud APIs from existing
infrastructure never surface in DNS records on the queried apex.
recon will not, and architecturally cannot, see these. The
[Backlog](#backlog-after-v20) carries the framing-side fixes that
make this limit visible to operators rather than hiding it.

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

### v1.7.0 — Hardened-target signal recovery *(shipped — see [CHANGELOG](../CHANGELOG.md))*

Squeezed more out of CT logs and resolution chains, and surfaced what
we already tracked but didn't expose. Surfaces: wildcard SAN sibling
expansion (`cert_summary.wildcard_sibling_clusters`), temporal CT
issuance bursts (`cert_summary.deployment_bursts`), CNAME chain motif
library (`chain_motifs` array), cross-source evidence conflict
surfacing (`evidence_conflicts` array). All shipped as YAML data
files plus minimal engine extension; the v2.0 schema lock promotes
each to stable per the disposition table below.

### v1.8.0 — Graph correlation *(shipped — see [CHANGELOG](../CHANGELOG.md))*

Built the structural layer on top of the v1.7 cert intelligence.
Surfaces: CT co-occurrence graph + Louvain communities
(`infrastructure_clusters`), fingerprint relationship metadata
(`product_family`, `parent_vendor`, `bimi_org` fields → emitted as
`fingerprint_metadata` map), batch-only hypergraph ecosystem view
(`ecosystem_hyperedges` when `--include-ecosystem`),
vertical-baseline anomaly rules (`expected_categories` /
`expected_motifs` on profiles, hedged-observation output),
`get_infrastructure_clusters` + `export_graph` MCP tools.
Zero new network surface; all derived from already-collected
observables. v2.0 promotes each to stable per the disposition table.

### v1.9.0 — Probabilistic fusion *(shipped, EXPERIMENTAL surfaces — see [CHANGELOG](../CHANGELOG.md), `docs/correlation.md` §4.8, `validation/v1.9-validation-summary.md`)*

Layered Bayesian inference on top of the deterministic engine, gated
behind `--fusion`. Surfaces (`posterior_observations`, `slug_confidences`,
`evidence_conflicts`, `--explain-dag`, `chain_motifs`,
`wildcard_sibling_clusters`, `deployment_bursts`,
`infrastructure_clusters`, `ecosystem_hyperedges`) are all marked
EXPERIMENTAL until the v1.9.x bridge milestones below close out and v2.0
locks the schema. The validation gate (corpus entropy reduction tracked
across releases; high-posterior calibration; interval coverage on
sparse-evidence cases) cleared on the v1.9.0 corpus run; per-node
calibration findings drove the v1.9.3 surgery.

### The path to v2.0 — a numbered sequence

v2.0 is the "polished and excellent everywhere" release: schema
lock + doc snapshot + zero EXPERIMENTAL labels anywhere. It is not
a parking lot for feature backlog. Every gated feature ships in a
v1.9.x patch first; v2.0 inherits each as already-present and
locks the shape.

The sequence below is the planned order from where we are now
(post-v1.9.3.10) to v2.0. Each version answers four questions:

- **What ships.** The concrete deliverable.
- **Why this is next.** The dependency chain that puts this
  version where it is, rather than later.
- **Quality bar.** Falsifiable acceptance criteria a reviewer can
  check before the patch tags.
- **Validation step.** How we know the patch is good before it
  ships, separate from the quality-bar checks.
- **Refinement.** What we'd revisit if the validation surfaced
  something the quality bar didn't predict.

Patches ship when their one version's work completes, not on a
fixed schedule. Multiple patches in a day is fine; bundled work
that combines unrelated stories is not (see Patch-release
discipline below). Bug-fix patches between versions claim the
next available `v1.9.X.Y` number and do not block the sequence.

Standing work runs alongside every version: catalog growth
(corpus-observed + vendor-doc-sourced), per-release calibration
aggregate published, CI / lint / typecheck / coverage gates.

#### v1.9.2 — UX validation via agentic QA *(shipped — see [CHANGELOG](../CHANGELOG.md) and `validation/v1.9.2-agentic-ux.md`)*

<details>
<summary>Shipped detail — methodology + findings</summary>

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

</details>

#### v1.9.3 — Resolve the `email_security_strong` definitional gap *(shipped — see [CHANGELOG](../CHANGELOG.md) and `validation/v1.9.3-calibration.md`)*

<details>
<summary>Shipped detail — topology surgery rationale</summary>

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

</details>

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
- **Numeric order IS delivery order.** The dependency chain is
  the point of the planning: hardened-adversarial validation
  (v1.9.4) informs the per-node stability decisions (v1.9.5),
  which inform CPT-change discipline (v1.9.6), which precedes
  the metadata-coverage gate flip (v1.9.7), which gates the
  richness pass (v1.9.8), which feeds the detection-gap UX
  surfaces (v1.9.9), which the stratified pre-lock validation
  (v1.9.10) verifies, which the doc-polish dry-run (v1.9.11)
  consolidates before v2.0 tags. Skipping ahead because a later
  patch "feels easier" means we're guessing at the dependency we
  just decided to think about.
- **Bug-fix patches use the next available number.** A regression
  fix that lands between v1.9.5 and v1.9.6 ships as `v1.9.5.1`
  or claims the next minor number — whichever the project's
  versioning strategy prefers at that moment. Bug fixes do not
  block bridge milestones, and bridge milestones do not block
  bug fixes; both make linear progress through their own number
  spaces.

EXPERIMENTAL labels come off per-node as the v1.9.4 → v1.9.11
sequence advances, not all at once. By the time v1.9.11 ships
(the doc-polish dry-run), every surface is either `stable`,
explicitly `experimental` (and we know why), or explicitly
`deprecated`. v2.0 then mechanically strips the remaining
EXPERIMENTAL language.

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

#### v1.9.8 — Catalog metadata richness pass

**What ships.** Description coverage raised to ≥ 80% across all
fingerprint files; reference coverage to ≥ 25%; non-default weights
documented per fingerprint with inline rationale. Pure data work
across `recon_tool/data/fingerprints/`, chunked into multiple PRs.

**Why this is next.** v1.9.7 turned the metadata-presence gate
enforcing; this version raises the floor from "every detection has a
description" to "every description is informative." Defenders read
the `--explain` panel to decide whether to act on a finding; a slug
labelled `auth0` without a description forces them to know what
Auth0's CNAME pattern looks like. v2.0 is the polished release;
shipping with description-less detections undercuts the explainability
priority.

**Quality bar.**
- [ ] Description rubric (in `CONTRIBUTING.md`): each detection's
  description states (a) what the slug detects, (b) the observable
  signal pattern, (c) common false-positive configurations if known.
  One sentence each; not boilerplate.
- [ ] References point to *vendor-published* DNS / MX / CNAME / TXT
  docs when possible (auditable third-party source), not blog posts.
  Where vendor docs are absent, link to the relevant RFC or a stable
  archived URL.
- [ ] Audit pass: every existing description re-read against the
  rubric, not just gap-filling. Placeholder descriptions ("Detects
  Foo") flagged and rewritten. Pass tracked in
  `validation/metadata-audit.md`.
- [ ] Chunked into PRs of ≤ 30 fingerprints each; no single mega-PR.
- [ ] Coverage check script reports both presence (v1.9.7 gate) and
  richness signals (mean description length, reference presence,
  non-default weight rationale). Richness is advisory; presence stays
  enforcing.

**Validation.** `scripts/check_metadata_coverage.py --report` after
the final PR lands shows ≥ 80% / ≥ 25% across identity, security,
infrastructure, productivity, email, AI, CRM, data-analytics,
verticals, and surface files. Trend per category logged.

**Refinement.** If the rubric forces boilerplate on niche slugs (an
internal API endpoint that doesn't merit three full sentences),
relax the rubric for that category and document the relaxation in
the audit log — don't game the gate with placeholder prose.

#### v1.9.9 — Detection-gap UX surfaces

**What ships.** Three operator-facing surfaces that make the
passive-DNS architectural limit visible:

1. **Passive-DNS ceiling phrasing.** When the default panel shows
   few services on a domain that the operator clearly expects to
   have many, the panel adds a one-line acknowledgement:
   "Passive DNS surfaces X public services; server-side API
   consumption, internal workloads, and SaaS without DNS
   verification are not observable from public DNS alone."
   Prevents "absence of finding = service not present" reading.
2. **Expanded subdomain enumeration breadth.** CT SAN-set traversal
   pulls subdomains from *all* observed apex certs (not just the
   queried apex's certs); the common-prefix wordlist extends to
   include `data`, `analytics`, `ml`, `ai`, `internal`, `ops`,
   `security`, `tools`; an optional CT search by org-name surfaces
   when one is available from a prior lookup.
3. **Apex-level multi-cloud rollup indicator.** When the
   `surface_attributions` span ≥ 2 cloud-categorized providers,
   a top-of-panel line reads: `Multi-cloud: 3 providers observed
   across the surface (AWS, Cloudflare, GCP)`. The detail lives in
   the existing Subdomain line (v1.9.3.10 counts); this rollup is
   the single-line scannable indicator.

**Why this is next.** v1.9.3.10 surfaced the unclassified-chain
gap and per-provider subdomain counts in the default panel. This
version completes the detection-gap surface story: the panel now
*shows what it cannot see* (the ceiling), *casts a wider net for
what it can see* (enumeration breadth), and *summarises the
distribution* (multi-cloud indicator). After v1.9.9 lands, the
default panel is honest about both its findings and its limits —
the v2.0 polish target.

**Quality bar.**
- [ ] Ceiling phrasing fires only when heuristics agree the panel
  is sparse for the apex's likely scale (e.g. domain_count ≥ 3 AND
  fewer than 5 categorized services). Conservative trigger; don't
  add the line to genuinely-small organizations' panels.
- [ ] Subdomain wordlist additions documented per term: which
  category of subdomain (data / ops / security / ai) and why it
  belongs in the common set. No speculative additions.
- [ ] Multi-cloud indicator counts distinct cloud-categorized
  providers, not distinct slugs. AWS CloudFront + AWS Route 53
  count as one (AWS), not two; the operator cares about cloud
  vendors at this rollup level, not service granularity.
- [ ] Tests cover the trigger heuristic (panel-sparse case), the
  expanded wordlist (resolves new subdomain class), and the rollup
  (collapses same-vendor slugs).

**Validation.** Re-run the v1.9.3.10 empirical sample (Stripe,
Shopify, Slack, Atlassian, Datadog, HashiCorp) plus 4 hardened-
adversarial apexes from the v1.9.4 corpus. Verify: ceiling phrasing
fires on the hardened apexes, not on the rich-stack ones (or fires
appropriately on both with different wording); subdomain
enumeration surfaces 10+ additional subdomains per rich-stack
apex; multi-cloud rollup fires on Stripe (AWS+Fastly+Stripe) but
not on a single-cloud target.

**Refinement.** If the ceiling phrasing fires on legitimate
single-cloud organizations and looks alarmist, tune the trigger
heuristic or change the wording. The point is to teach operators
about the architectural limit, not to suggest something's wrong.

#### v1.9.10 — Stratified-corpus pre-lock validation

**What ships.** A 60-domain stratified validation suite across six
vertical/cloud strata, run against the v1.9.9 build to confirm the
catalog and the new UX surfaces hold up before the v2.0 schema
lock. Output: a per-stratum coverage report
(`validation/v1.9.10-pre-lock.md`) plus a trend table tracking
multi-signal correlation depth from v1.6 → v1.9.10 per stratum.

**Why this is next.** Up to now, validation has been single-corpus
(enterprise M365/AWS-skewed) plus one small rich-stack empirical
pass (v1.9.3.10). The v2.0 schema lock is the moment to confirm
the engine works across cloud strata, not just the ones our
historical corpus over-represented. A stratum where the engine
performs poorly is information the v2.0 release should disclose
explicitly, not hide.

**Quality bar.**
- [ ] Strata: known-GCP customers (10), known-Azure non-O365 (10),
  known-Oracle customers (10), known-Alibaba customers (10),
  known-PaaS / Vercel / Netlify (10), known-SSE/SASE-fronted (10).
  Each stratum's 10 domains are publicly-documented users of that
  vendor sourced from vendor case-studies, vendor blog posts, or
  job listings; no proprietary intel.
- [ ] Per-stratum coverage metric: fraction of domains where
  recon's `Cloud` line correctly names the expected cloud vendor
  for that stratum.
- [ ] Per-stratum unclassified-termini count: zero is great; > 0
  identifies catalog gaps that need filling before v2.0.
- [ ] Trend table per stratum across v1.6 → v1.9.10, even if the
  earlier versions need to be re-run against the new strata.
- [ ] Aggregate findings published in
  `validation/v1.9.10-pre-lock.md`.

**Validation.** The validation IS the version's deliverable. The
quality bar replaces "validation step".

**Refinement.** If a stratum surfaces ≥ 3 unclassified termini,
v1.9.10 ships a follow-up catalog-growth patch (v1.9.10.1) before
v1.9.11 starts. If a stratum has < 50% Cloud-line agreement,
investigate: is the catalog missing entries, or is the cloud's
public DNS surface genuinely too thin to detect?

#### v1.9.11 — Documentation polish dry-run

**What ships.** Every doc reviewed against the v2.0 quality bar
before v2.0 actually tags. correlation.md polished to the v2.0
draft form (defense ↔ correlation mapping table, prior-art
comparison, dependency-floor manifesto, failure-mode catalog).
README, CONTRIBUTING, AGENTS.md, docs/mcp.md, docs/legal.md,
docs/security.md cross-checked for stale references, dead links,
EXPERIMENTAL labels in user-facing text. Migration guide for
v1.x → v2.0 consumers added (`docs/migration-v2.md`) covering the
EXPERIMENTAL → stable field promotions, the dropped Bayesian-
network nodes that didn't clear v1.9.5, and the schema-version
bump.

**Why this is next.** v2.0 should be a *mechanical* lock-and-tag
event, not a "let's also rewrite docs" event. If the v2.0 docs are
already polished, the lock just bumps the schema version, strips
EXPERIMENTAL labels from code/JSON descriptions, and tags. Doing
the doc work as v1.9.11 separates the rewriting from the
mechanical lock.

**Quality bar.**
- [ ] Zero EXPERIMENTAL labels in any doc, panel string, CLI help
  text, MCP tool description, or schema field description.
  Verified by `grep -ri experimental` returning zero user-facing
  hits (internal test markers excepted).
- [ ] All v1.9.x backlog items either shipped or moved to the
  post-v2.0 Backlog. No "we'll fix this in v1.9.x" forward-looking
  text remaining in user-facing docs.
- [ ] Every cited prior-art reference in correlation.md is
  reachable (no dead links); every dependency in the
  dependency-floor manifesto matches `pyproject.toml`'s actual
  dependency list (no manifesto/code drift).
- [ ] Every CONTRIBUTING.md procedure is tested by following it
  literally — a maintainer walks through "add a new fingerprint"
  using only the CONTRIBUTING.md text; gaps in the procedure
  surface here, not after v2.0 ships.
- [ ] Migration guide covers (a) the EXPERIMENTAL field promotions
  by name, (b) dropped Bayesian-network nodes from v1.9.5
  dispositions, (c) schema-version bump, and (d) a downgrade-path
  recommendation for consumers who can't move yet.

**Validation.** Run the entire v1.9.3.10 empirical sample plus the
v1.9.10 stratified suite ONE MORE TIME on the v1.9.11 build with
all docs reflecting v2.0 state. No code change between v1.9.11 and
v2.0 should be required.

**Refinement.** If the docs review surfaces gaps in the code (e.g.
a docstring describes behaviour the code doesn't implement),
v1.9.11 ships a follow-up code patch before v2.0 starts. The
v2.0 release notes should read like an inventory, not a feature
list — every claim should already be true at v1.9.11 tag time.

_Additive feature candidates (BIMI VMC clustering, MCP delta helper,
self-audit batch mode, non-MCP graph exports, per-node
`n_eff_multiplier`, corpus-driven Hypothesis tests, Hawkes-kernel
CT burst classification, LPA fallback for `infra_graph`, explicit
ignorance mass, noisy-OR / noisy-AND CPT gates) are now in the
[Backlog (after v2.0)](#backlog-after-v20) section. They were
previously framed as "optional v1.9.x feature additions"; under
the v1.9.4 → v2.0 linear sequence, they no longer claim slots in
the path-to-v2.0 plan. Any of them may be promoted into a
post-v2.0 v2.x.y patch when there's a falsifiable defensive case
and corpus evidence to back it._

### v2.0.0 — Maturity

Lock in what the previous releases proved. Promote stable experimental
fields to the v2.0 schema contract; make the catalog community-PR-
friendly; ensure the framework is suitable for sustained corpus-driven
operation.

**Pre-conditions** — the v1.9.4 → v1.9.11 linear sequence has
completed, in order:

1. **v1.9.4** — Hardened-adversarial behaviour validated; 50-domain
   minimal-DNS corpus exercises the asymmetric-likelihood design.
2. **v1.9.5** — Per-node stability dispositions decided for every
   Bayesian-network node; "not yet" nodes either redefined,
   deprecated, or removed.
3. **v1.9.6** — CPT-change discipline documented in
   `CONTRIBUTING.md` and enforced in review.
4. **v1.9.7** — Metadata-coverage gate flipped from advisory to
   presence-enforcing.
5. **v1.9.8** — Catalog metadata richness: descriptions ≥ 80%,
   references ≥ 25%.
6. **v1.9.9** — Detection-gap UX surfaces shipped: passive-DNS
   ceiling phrasing, expanded subdomain enumeration breadth,
   apex-level multi-cloud rollup indicator.
7. **v1.9.10** — Stratified-corpus pre-lock validation passed:
   60-domain stratified suite (per-cloud × 6 strata) shows the
   engine works across cloud customers, not just the
   enterprise-M365/AWS-skewed historical corpus.
8. **v1.9.11** — Documentation polish dry-run: every doc reviewed
   against v2.0 quality bar; migration guide drafted; zero
   EXPERIMENTAL labels remain in any user-facing text.

Each version's prose above documents its own quality bar,
validation step, and refinement check.

Already cleared en route to this sequence:

- ~~v1.9.2 (operator UX validation via agentic QA)~~ — see
  `validation/v1.9.2-agentic-ux.md`.
- ~~v1.9.3 (email_security_strong definitional gap)~~ — see
  `validation/v1.9.3-calibration.md`.
- ~~Supply-chain hardening, SBOM, secrets-scanning, forward-compat
  cache test~~ — shipped in v1.9.3.1.
- ~~Top-3 influential edges in --explain-dag~~ — shipped in v1.9.3.2.
- ~~Cloud-vendor coverage gap fill (GCP / Azure non-O365 / Oracle
  / IBM / Alibaba / PaaS / SSE-SASE / identity extras; 29 new
  fingerprints)~~ — shipped in v1.9.3.9.
- ~~Subdomain-level surface intelligence in default panel
  (unclassified-surface section + per-provider counts)~~ —
  shipped in v1.9.3.10.
- ~~Downstream consumption examples (Splunk + Elasticsearch field
  mappings, CI gate against schema drift)~~ — shipped in v1.9.3.8.

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

**Detection-gap framing & enumeration breadth** *(added 2026-05-11
following empirical validation pass against rich-stack public
companies):*

- **Passive-DNS ceiling phrasing in the panel.** When the default
  panel lists few services on a domain that public knowledge suggests
  uses many, surface a one-line acknowledgement: "Passive DNS surfaces
  X public services; server-side API consumption, internal workloads,
  and SaaS without DNS verification are not observable from public
  DNS alone." Prevents "absence of finding = service not present"
  reading. The architectural Category-1 limit becomes visible without
  needing the operator to know the invariants. Backlog because the
  trigger heuristic ("when does the panel hint at the ceiling?") is
  policy and deserves explicit design.
- **Subdomain enumeration breadth.** Today's related-domain discovery
  is CT-driven + a fixed common-prefix probe. A customer with
  `data-pipeline.example.com → GCP` whose subdomain doesn't appear in
  CT and isn't a common prefix is invisible. Expand: pull SAN sets
  from ALL observed apex certs (not just the queried apex), longer
  common-prefix wordlist (security, ops, internal, ml, ai, data,
  etc.), and a CT search by org name when one is available from a
  prior lookup. None violates passive-only. Backlog because the
  optimal wordlist + CT-query plan needs corpus-driven calibration.
- **Stratified-corpus validation as standing practice.** Single
  private corpus has bias; stratified samples (known GCP-customer set,
  known Azure-customer set, etc.) surface the bias by design. Process
  change in `validation/` — not code. Backlog because the per-cloud
  10-domain reference sets need curation; vendor case-studies are the
  starting input.
- **Cloud-provider rollup at the apex level.** When subdomains span
  multiple clouds (apex on Cloudflare, subdomains across AWS + Fastly
  + Stripe), the v1.9.3.10 "Subdomain" line shows counts. A natural
  extension is a top-of-panel `Multi-cloud` indicator: "5 cloud
  providers observed across the surface". Backlog because the
  threshold for "multi-cloud" is policy.

**Additive feature candidates** *(moved from the former
"v1.9.x optional feature additions" section when the roadmap
restructured to a flat sequence; any of these may be promoted into
a post-v2.0 v2.x.y patch when there's a falsifiable defensive case):*

- **BIMI VMC legal-name clustering** — pairs with the v1.8
  hypergraph view; demonstrates real multi-brand identification on
  a private corpus.
- **MCP delta helper** — `recon_delta(domain_or_json_a,
  domain_or_json_b)` MCP tool. Compares supplied or cached JSON
  only; no hidden network. Optional `include_fusion` flag surfaces
  v1.9 posterior shifts alongside the deterministic diff.
- **Portfolio / self-audit batch mode** — `recon batch --self-audit`
  aggregating vertical-baseline hits, anomaly rules, correlation-
  depth distribution, and gateway / sovereignty consistency across
  many domains in one summary. A lightweight agent-side precursor
  ships today in `AGENTS.md` / `SKILL.md` under the
  "Family-of-companies / portfolio rollup" workflow — agents
  synthesize the rollup from per-domain JSON returned by
  `recon batch --json --include-ecosystem`. Promoting to Python
  gives deterministic, testable output emitted as schema fields;
  worth doing once the agent-side rollup has validated the report
  shape on a private corpus. Operator-supplied apex list in both
  versions; recon never infers the corporate-family relationship.
- **Non-MCP graph exports** — Mermaid diagram output for the v1.8
  cluster graph, plus CSV exports for relationship metadata and
  chain motifs.
- **Per-node `n_eff_multiplier` in `bayesian_network.yaml`** —
  schema-additive field that scales effective sample size on a
  per-node basis. Lets weak-calibration nodes widen their credible
  intervals without globally widening every node. May be promoted
  into a pre-v2.0 patch if v1.9.4 hardened-adversarial findings +
  the existing sensitivity test surface nodes whose interval shape
  only makes sense with per-node scaling.
- **Corpus-driven Hypothesis tests** — extend
  `tests/test_bayesian_hypothesis.py` with property tests over real
  corpus output. Strengthens the test floor.
- **Hawkes-kernel CT burst classification** — fit a one-parameter
  exponential-decay kernel to each cluster's CT timestamps and
  classify `automated_renewal` vs `manual_deployment`. Surface as
  `cert_summary.deployment_bursts[].kernel_class`.
- **Asynchronous Label Propagation fallback for `infra_graph`** —
  pure-Python LPA replaces the connected-components fallback above
  the 500-node Louvain cap, keeping community structure visible on
  10k+-node graphs.
- **Explicit ignorance mass (epistemic vs aleatoric)** — Dempster-
  Shafer-style mass on the "don't know" state, computed from the
  ratio of unbound to bound evidence nodes for that posterior;
  surfaces in `--explain-dag` as a third quantity alongside
  posterior and interval.
- **Noisy-OR / noisy-AND CPT gates** — schema-additive
  `gate: noisy_or | noisy_and | custom` on multi-parent CPTs in
  `bayesian_network.yaml`. Compact and human-reviewable as the
  network grows beyond ~10 nodes.

**Pre-existing backlog:**

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
- **Machine-readable CLI surface inventory for downstream skill
  and agent authors.** Two small additions captured here from
  feedback on the v1.9.6 release:
  1. A "Tool surface changes" one-liner per release in the
     CHANGELOG, focused on the user-visible CLI surface (new
     subcommands, new flags). Lets skill maintainers do a
     30-second sync check between releases without diffing
     `recon --help` output. The current CHANGELOG mixes
     surface changes into the narrative; a single-line
     callout per release would be more scannable.
  2. A `docs/cli-surface.md` (or `recon --help-extended`)
     canonical reference: every flag and subcommand with a
     one-line description, suitable for copy-paste into
     skill files or AI agent prompts. Today the info is
     split across README excerpts, `recon --help`, and
     `docs/mcp.md`. A consolidated reference removes that
     scatter.

  Explicitly out of scope for this entry: Claude-skill-
  specific or agent-behavior guidance in the repo. That
  layer lives in the per-client skill files under `agents/`
  (and the portable `AGENTS.md` at the repo root). The
  recon repo's job here is to be the source of truth for
  the tool's surface, machine-readable; the skill's job is
  to translate that surface into agent behavior.

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
