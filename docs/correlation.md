# Correlation engine

Reference for security architects, researchers, and contributors who want to
understand how recon turns scattered passive observables into hedged
intelligence — and why the design stays defensive-first by construction.
Casual users do not need this document; the README and `--explain` output
cover everyday use.

This file is a living draft. It mirrors the current implementation and the
[build plan](roadmap.md#build-plan) (v1.7.0 through v2.0.0). The polished
snapshot is itself a v2.0.0 deliverable — until then, sections will move and
sharpen as features land.

## 1. What recon is doing, formally

recon is an **external attack-surface management (EASM) instrument** for
defenders. The premise: the defender has already applied legal and technical
obscurity to their own public footprint. The question recon answers is *how
much of that footprint is still observable to anyone with public DNS and
certificate-transparency access* — i.e., how effective is the obscurity in
practice.

Underneath the panel output, the tool is doing latent-variable inference.
Let

  $G = (V, E, \Theta)$

be the latent organizational technology graph we want to recover:

  - $V$ — domains: the queried apex plus everything discovered via
    common-subdomain probes, CNAME chains, and CT SAN sets.
  - $E \subseteq V \times V$ — relationships inferred from the observables:
    shared CNAME-chain hops, shared certificate batches, shared identity-
    discovery responses, BIMI VMC organization, etc.
  - $\Theta$ — per-node and per-edge attribute vector: detected service
    slugs, evidence DAG, confidence, hedge level.

The observables we get to look at are intentionally narrow:

  $O = \{$ DNS RRsets (A, CNAME, MX, NS, TXT, SPF, DMARC, DKIM, BIMI),
        CT log entries (issuer, SAN sets, `not_before` timestamps),
        unauthenticated identity-discovery endpoints (M365, Google) $\}$

The task is to compute or approximate $p(\Theta \mid O)$ — the posterior
over the latent stack given the public broadcast channel — such that the
defender ends up with the tightest credible bounds on their own residual
exposure that the public channel allows. Strictly passive: no probes
beyond what is already standard public-DNS resolution, no credentials,
no learned ML weights, no imported intelligence databases.

## 2. Why this objective is the right one for defenders

The information-theoretic quantity we care about is

  $I(\Theta; O) = H(\Theta) - H(\Theta \mid O)$

where $H(\cdot)$ is Shannon entropy and $I(\Theta; O)$ is the mutual
information between the latent stack and the public channel. The
defender's hardening strategy is, in information-theoretic terms, a
deliberate effort to minimize $I(\Theta; O)$ — they want to broadcast
as little structural information as possible.

recon's correlation work is the counter-strategy: extract the bits that
remain. Each new feature in the build plan is a feature extractor that
maximizes information gain per observable, subject to two hard
constraints:

  1. The output must be **fully traceable** — every conclusion is
     reachable through the evidence DAG (`--explain`).
  2. The output must be **honestly calibrated** — sparse evidence
     produces wider hedges, denser evidence produces firmer ones, and
     "we cannot tell from this channel" is a valid result.

This is Bayesian epistemic humility applied to passive observation.
The tool is not claiming knowledge of $\Theta$; it is reporting how much
$O$ has reduced its uncertainty about $\Theta$, and showing the
defender exactly which observables drove the reduction.

## 3. Current implementation (v1.6.1)

Everything that ships today is **deterministic rule-based fusion**. There
is no probabilistic graphical model, no temporal feature, no graph layer.
The architecture is:

  - `recon_tool/sources/dns.py` — collects DNS observables and the
    CNAME chains used by the surface-attribution pipeline.
  - `recon_tool/sources/cert_providers.py` — pulls CT entries from
    crt.sh and CertSpotter; surfaces SAN sets and basic cert summary
    statistics.
  - `recon_tool/fusion.py` — multi-source evidence merge into per-slug
    detections.
  - `recon_tool/merger.py` — deduplicates SourceResults into a single
    TenantInfo with full provenance and a `MergeConflicts` record when
    sources disagree.
  - `recon_tool/signals.py` — applies YAML rules (`requires`,
    `min_matches`, `expected_counterparts`) to produce signal-layer
    observations on top of fingerprint slugs.
  - `recon_tool/absence.py` — negative-space rules: when *expected*
    evidence is absent, surface the absence as an observation.
  - `recon_tool/posture.py` — neutral aggregation into the posture
    panel (Email / Identity / Infrastructure / SaaS / Consistency).
  - `recon_tool/clustering.py` — simple related-domain grouping for
    batch mode and chain expansion.
  - `recon_tool/discovery.py` — surface-attribution and gap-mining
    layer added in v1.5; the building block the discovery loop
    (`recon discover`, `validation/scan.py`) sits on top of.
  - `recon_tool/explanation.py` — provenance DAG serialization for
    `--explain` and the MCP `explanation_dag` field.

For most domains, deterministic fusion is the right tool. It is fast,
explainable, audit-able, and catches the high-confidence cases without
requiring any probabilistic machinery. The cases it misses are the
hardened ones: targets that publish minimal DNS, randomize CNAME
chains, rotate short-lived certs, and use wildcard certificates to
collapse SAN inventory. That is where the build plan focuses.

## 4. Extensions in the build plan

Every extension below is a feature extractor over $O$ that recovers
information the current deterministic engine misses on hardened
targets. Each lands as a YAML schema extension plus minimal engine
code, ships gated behind an explicit flag where the output is
experimental, and stays inside the invariants ([roadmap.md §
Invariants](roadmap.md#invariants)).

### 4.1 Wildcard SAN sibling expansion (v1.7.0)

When a CT entry contains `*.example.com`, the rest of the SAN list in
the same certificate is a candidate sibling set. Wildcards exist
specifically to collapse SAN inventory, so they look like obscurity —
but the surrounding SAN entries in the same issuance are still public.

The defensive value: a defender who relies on wildcard certs to hide
their subdomain map can use recon to confirm that "wildcard hides
everything" is not actually true once you read the cert metadata
carefully. Each sibling lands as `related_domains` evidence with type
`ct_san_sibling` and the source cert's `not_before`. Hedged: "issued
together; common ownership not implied" — same-cert SAN sets are
sometimes shared across multiple tenants of the same hosting
provider, so the rule informs but does not assert.

### 4.2 Temporal CT issuance bursts (v1.7.0)

Treat issuance as a point process on the timeline. For a given apex or
issuer, the timestamps $\{t_1, \dots, t_n\}$ are observable. Define a
burst as a connected component of the inter-arrival graph with edge
threshold $\Delta t < \tau$ (DBSCAN-style; $\tau$ on the order of
minutes for typical deployment cadence).

Co-issued subdomains within a burst become directed edges in the
evidence DAG, weighted by an inverse-time function $w_{ij} \propto
1/\Delta t_{ij}$. Output language describes the observation neutrally:
"co-issued within $\tau$ seconds" — never "same owner". The motif
survives short-lived rotation because relative timing is preserved
across reissuances.

Defensive value: detects deployment cadence even when the underlying
hostnames are randomized or short-lived. A defender running a
hardened-but-noisy infrastructure can use the burst signal to verify
that operational coordination is or is not visible from the outside.

### 4.3 CNAME / NS chain motifs (v1.7.0)

Each resolution path is a directed string $\pi(d) = h_1 \to h_2 \to
\dots \to h_k$ where $h_i$ is the $i$-th CNAME or NS hop. recon
already walks chains for surface attribution; v1.7.0 adds a motif
library (`recon_tool/data/motifs.yaml`) describing recurring vendor-
order patterns: `cloudflare → akamai → custom-origin`,
`fastly → azure-fd`, etc.

Pattern matching is regex over the chain string or simple subgraph
isomorphism on the per-domain chain graph. Chain length is capped at
4 to prevent motif explosion. Vertical-aware absence rules can also
fire on motifs: a fintech profile expecting a WAF motif will surface
the absence as a hedged observation, never a verdict.

Defensive value: even with randomized intermediate labels, recurring
edge-stack signatures persist. Multi-hop proxy strategies leak
through their structural pattern even when individual hops look
bespoke.

### 4.4 Cross-source evidence conflict surfacing (v1.7.0)

`MergeConflicts` already records when two sources disagree about a
field (display name, auth type, region, tenant ID, DMARC policy,
Google auth type). v1.7.0 makes those conflicts a top-level field
in `--json` output (`evidence_conflicts`) and a section in
`--explain`.

Defensive value: a defender may publish minimal DNS but have CT
records that contradict it. The conflict matrix is exactly where
hardening hygiene gaps surface. Output is neutral: "DNS reports X,
CT shows Y" — the meaning is for the operator to interpret, not
for recon to claim.

### 4.5 CT co-occurrence graph + Leiden community detection (v1.8.0)

Build an in-memory undirected multi-graph $G_{CT} = (V_{CT}, E_{CT})$
across the corpus or the chain-expanded set:

  - $V_{CT}$: domains observed in CT SAN sets.
  - $E_{CT}$: weighted by shared cert ID, shared issuer, and
    temporal proximity (the burst rule from §4.2).

Run Leiden community detection (modularity maximization with the
resolution parameter we expose):

  $Q = \frac{1}{2m} \sum_{ij}\left[A_{ij} - \frac{k_i k_j}{2m}\right]
  \delta(c_i, c_j)$

The output is a set of communities $C_1, \dots, C_k$ along with the
modularity score $Q$. The score is the calibrated handle on
"strength of shared infrastructure boundary" — a high $Q$ means
recon is confident the partition is meaningful; a low $Q$ means the
partition is essentially a coin flip. Both are useful.

Implementation notes: pure-Python `networkx`, capped at ~500 nodes
per cluster pass with deterministic fallback to the existing simple
clustering when over-cap. The dependency is acceptable —
`networkx` ships no learned weights and no aggregate-intelligence
data, just graph algorithms.

Defensive value: defenders relying on wildcard certs across
brand-sibling domains can see exactly which certificates pin them
together. Hardened targets can validate that their PKI segmentation
holds at the public observation layer.

### 4.6 Hypergraph ecosystem view (v1.8.0, batch-only)

For corpus runs, treat the entire batch as a hypergraph
$\mathcal{H} = (V, \mathcal{E})$:

  - $V$: every queried apex plus discovered domains.
  - $\mathcal{E}$: hyperedges whose members share an issuer, a
    fingerprint set, and a BIMI VMC organization.

Hyperedge size encodes "how many co-located organizations sit
behind the same broadcast signature". Set-intersection counting
(or `hypernetx` if we eventually want richer hypergraph
algorithms) recovers multi-brand orgs that single-domain views
cannot reach.

Surfaced only behind `--include-ecosystem` to keep JSON size
predictable on small runs. The output describes observed
co-membership — not corporate ownership.

### 4.7 Vertical-baseline anomaly rules (v1.8.0)

Each entry in `verticals.yaml` defines an expected fingerprint
distribution per profile (fintech, healthcare, saas-b2b, etc.). At
runtime we compare the observed signal mix against the baseline.
The simplest formulation is a KL-divergence proxy over the
vertical-relevant slugs; in practice we ship readable rules
(`expected: WAF`, `expected: identity_provider`, etc.) and let the
explanation layer surface the deviation in neutral language
("fintech profile expects WAF motif; not observed for this apex").

Anomalies are observations, not verdicts. The wider the vertical,
the wider the hedge.

### 4.8 Bayesian network fusion layer (v1.9.0, experimental)

Define a small DAG $\mathcal{B}$ whose nodes are fingerprint slugs
and signals, and whose edges carry conditional probability tables
(CPTs). The CPTs live in `bayesian_network.yaml` — human-readable,
committed as data, hand-tuned with Dirichlet priors derived from the
private corpus. Never learned weights, never auto-trained, never
shipped binaries.

Inference is exact via variable elimination for $|\mathcal{B}|
\leq 20$:

  $p(\text{slug} \mid O) = \frac{1}{Z} \prod_{i} \phi_i(O,
  \text{parents})$

Output: a posterior mean and credible interval per slug, replacing
the deterministic point score in the experimental output path. The
v1.0 default JSON shape is untouched. Sparse-evidence cases produce
wider intervals and surface the passive-observation ceiling
directly in the explanation, so a confident-looking number cannot
imply more than the evidence supports.

Cross-source conflicts (§4.4) feed the posterior as probabilistic
dampeners: when DNS and CT disagree about a slug's presence, the
interval widens until the conflict resolves.

Calibration discipline: the layer ships behind the existing
`--fusion` flag and stays EXPERIMENTAL until at least two corpus
runs validate that high-posterior predictions match observable
evidence and that intervals cover sparse-evidence cases without
collapsing on dense-evidence ones.

### 4.9 Feedback-driven priors (v1.9.0, local only)

A corpus run can update a local prior file at
`~/.recon/priors.yaml` based on the validation run's findings.
Three guardrails:

  1. The priors file lives only on the operator's machine.
  2. The package never ships learned weights — only the corpus
     metadata that produced them, and only as documentation.
  3. There is no remote service. There is no telemetry. There is
     no shared reputation database.

This is "tune your local priors against your own corpus" —
specifically not "build a community-wide trust model". The
distinction is invariant.

## 5. Epistemology and the design choices that follow

Three principles connect the math above to the design constraints
the project ships under:

  1. **The public channel is adversarial by design.** A hardened
     defender minimizes $I(\Theta; O)$ as a deliberate strategy.
     recon's correlation work is the principled counter-strategy:
     extract the structural information that no public broadcast
     can avoid leaking (CT logs are append-only and globally
     visible; DNS delegation is hierarchical; issuance timing is
     governed by operational physics). It is not "clever hacks"
     against defenders; it is the defender themselves running
     their own counter-analysis.
  2. **Hedging is a calibration choice, not politeness.** Confident-
     looking output on sparse evidence is a calibration failure.
     The Bayesian layer enforces this in numbers (wider intervals
     under sparse evidence); the deterministic layer enforces it in
     language (`--confidence-mode strict` only fires when evidence
     is dense; sparse output stays qualified). Both are the same
     idea expressed in two registers.
  3. **Provenance is non-optional.** Every conclusion is reachable
     through the evidence DAG. The `--explain` output and the
     `explanation_dag` JSON field exist so a security architect
     can reconstruct exactly which observable produced which
     observation. A black-box posterior — even a numerically
     correct one — is unacceptable, because the defender cannot
     audit it. This rules out ML embeddings, learned weights, and
     any "trust the score" pattern.

These principles are why the invariants are what they are. They are
not arbitrary engineering taste — they are direct consequences of
treating recon as defensive epistemic infrastructure rather than as
a recon (offensive) tool.

## 6. How to read recon output through this lens

  - **Default panel** — the posterior mode + maximum-confidence
    slugs the deterministic engine extracted. Suitable for everyday
    review.
  - **`--full`** — the broader observation set, including
    surface-attribution map and the External surface section that
    walks each related subdomain's CNAME chain.
  - **`--explain`** — the evidence DAG. This is the authoritative
    answer to "why did recon say this?". Every conclusion is
    traceable to its observables.
  - **`--json` with `--include-unclassified`** — the discovery
    surface. Unclassified CNAME chains are observables we found but
    cannot yet attribute; they feed the validation loop and the
    `/recon-fingerprint-triage` skill.
  - **`--fusion`** *(experimental, v1.9.0+)* — Bayesian posteriors
    with credible intervals. Read intervals, not just means.

## 7. Alignment with invariants

Every extension above is gated by:

  - **Passive only.** No new probes beyond standard public-DNS
    resolution.
  - **Zero credentials, zero API keys, zero paid APIs.** Every
    source is reachable without an account.
  - **No bundled ML weights, embeddings, ASN/GeoIP databases, or
    aggregate intelligence.** The Bayesian layer ships data-file
    CPTs and exact inference; the graph layer ships data-file motif
    rules and a public graph algorithm. Neither is a learned model.
  - **No user-code plugin system.** Custom fingerprints, signals,
    motifs, and CPTs are data files only.
  - **Hedged output with full DAG provenance.** Sparse evidence
    stays qualified; dense evidence can be firmer; "we cannot tell
    from this channel" remains a valid result.

See [roadmap.md § Implementation discipline](roadmap.md#implementation-discipline-for-new-correlation-work)
for the per-PR checklist that turns these invariants into shippable
behavior.
