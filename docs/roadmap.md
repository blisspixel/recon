# Roadmap

recon is a passive domain-intelligence CLI and MCP server. The
roadmap below is what comes next, in priority order, from where the
tool is now. Shipped work lives in [CHANGELOG.md](../CHANGELOG.md) —
this file is about the *next* release and the path to 1.0, not a
retrospective.

## Invariants (non-negotiable)

- **Passive only.** No active scanning, no port probes, no zone
  transfers, no TLS handshakes against target infrastructure.
- **Zero credentials, zero API keys, zero paid APIs.** Every data
  source must be reachable without an account.
- **No bundled ML models, no bundled embeddings, no bundled
  ASN/GeoIP data.**
- **No aggregated local database.** Per-domain JSON files in
  `~/.recon/` are fine — a shared sqlite/duckdb store is not.
- **Hedged output only, but not aggressive hedging on dense
  evidence.** The tool should neither overclaim on sparse data nor
  mumble on strong data. A `--confidence-mode strict` escape hatch
  lets users drop hedging only when evidence density is high.

Anything new must fit inside this box. If it doesn't, it doesn't
ship.

## Priority order

Correctness → reliability → explainability → composability → new
features. A feature that compromises reliability waits.

## What's next

Four items, in priority order. The first is the single biggest
reliability weak spot recon has right now.

### 1. CT source resilience

Today recon leans on `crt.sh` with a `CertSpotter` fallback for
certificate-transparency data — and CT data is roughly 40% of what
gives the tool its value (related domains, subdomain taxonomy,
temporal evidence). Both providers flake together often enough that
this is a first-day pain point, not a "later" problem.

- *Files:* `sources/cert_providers.py`, new `recon_tool/ct_cache.py`,
  `resolver.py`.
- *Change:* Add a third zero-creds CT provider behind the existing
  `CertIntelProvider` protocol (candidates: Merklemap, Google's CT
  log viewer, or the raw CT API via `certificatetransparency.dev` if
  its API stays unauthenticated). Add a per-domain JSON cache at
  `~/.recon/ct-cache/{domain}.json` with a seven-day default TTL —
  one file per domain, no aggregated store. On a degraded-source
  path, fall back to the cache before returning an empty result.
- *Done when:* A three-provider fallback chain is wired up, the
  per-domain cache round-trips through the same `tenant_info_to_dict`
  path the main cache uses, and a simulated triple-provider outage
  still returns the last known subdomain set with an explicit "from
  local cache (age N days)" note on the panel.

### 2. Community fingerprint pipeline

The fingerprint database is 212 entries maintained by one person.
That scales for now. It won't scale for long. A community
contribution path has to exist before 1.0, not after.

- *Files:* new `CONTRIBUTING.md` section on fingerprints, new
  `scripts/validate_fingerprint.py`, new GitHub issue / PR template
  (when the project moves to accepting them).
- *Change:* Document the fingerprint YAML schema in a single place.
  Publish a PR template that runs the existing Hypothesis-based
  property test harness against any new fingerprint and rejects
  contributions that introduce false positives on the sparse-data
  corpus. Add a `scripts/validate_fingerprint.py` that runs the
  same checks locally, so contributors can iterate before opening
  a PR.
- *Done when:* A new fingerprint contributor can run one local
  command to know whether their YAML passes; a CI workflow gates
  merges on the same check; and `CONTRIBUTING.md` explains the
  additive-only invariant (custom fingerprints extend, never
  override built-ins).

### 3. `--confidence-mode strict`

The hedging language is correct on sparse data and too noisy on
dense data. A CISO looking at a Fortune-100 target with four
corroborating sources doesn't need "observed" and "fits a pattern"
on every line — the evidence density already carries the confidence.

- *Files:* `cli.py`, `formatter.py`, `insights.py`.
- *Change:* Add a `--confidence-mode` flag (default: `hedged`, the
  current behaviour). A new `strict` mode drops the hedging
  qualifiers on any observation that meets both of:
    - at least three independent successful sources contributed, AND
    - the slug's detection score is `high` (three or more distinct
      evidence source types for that slug).
  Sparse-data output is untouched. The invariant "never overclaim
  when evidence is thin" stays load-bearing and is enforced by the
  existing property-based hedging harness, which runs against both
  modes.
- *Done when:* `recon contoso.com --confidence-mode strict` on a
  dense-evidence target drops the "observed" / "likely" qualifiers
  on signals with three-or-more-source corroboration; the same flag
  on a sparse-evidence target produces identical output to the
  default mode (no change); the hedging harness passes against both
  modes.

### 4. Bayesian evidence fusion (experimental, not blocking 1.0)

The probabilistic fusion layer that was originally in the old
roadmap. It's still a good idea, but not a 1.0 blocker. Ship it as
**experimental** in 1.0 if the math is ready; otherwise push to 1.1.

- *Files:* `merger.py`, new `recon_tool/fusion.py`, `models.py`.
- *Change:* Per-source reliability priors + Beta conjugate update
  for per-slug confidence. Pure numpy, no Pyro / NumPyro. Output a
  `slug_confidences` float field on `TenantInfo`, tagged
  **experimental** in `docs/stability.md` so it can evolve in
  minor releases without breaking SemVer.
- *Done when:* The fusion layer is opt-in via a single flag, the
  output is tagged experimental, and the property-based harness
  asserts that two corroborating sources always yield a strictly
  higher posterior than either alone.

## 1.0 — stability commitment

Ship 1.0 when the four items above are stable, not when every item
on the old roadmap is done. The old roadmap stacked property-graph
core, counterfactual DAGs, temporal CT, synthesis-module collapse,
and more all as 1.0 blockers. That's gold-plating. Most of those
are refactoring or experimental features that should ship as 1.x
minor releases *after* 1.0 proves the contract surfaces hold.

The 1.0 commitment is small and concrete:

1. **Frozen public surfaces.** CLI flags, `--json` output field
   names and types, MCP tool names and parameter shapes, YAML
   schemas for fingerprints / signals / profiles, config file
   locations. Each surface tagged **stable** or **experimental**
   in a single `docs/stability.md`. Breaking any stable surface
   requires a 2.0 and a deprecation window.
2. **SemVer + Python support policy.** Documented. Python version
   support window matches CPython's own N-2 policy.
3. **Security threat model.** One page in `docs/security.md`
   covering trust boundaries, attack surface, mitigations,
   out-of-scope.
4. **Known limitations.** One page in `docs/limitations.md`
   covering what the tool doesn't see, what it underclaims on,
   and when to reach for something else.
5. **Release process.** Documented checklist, a simple
   `scripts/release.py` with confirmation prompts at each
   destructive step, complete PyPI metadata.
6. **Community fingerprint pipeline** (from "What's next" item 2
   above).
7. **CT resilience** (from item 1).

**Metrics that matter for 1.0:**
- ≥80% signal coverage on the hardened enterprise test corpus.
- Zero unhedged assertions on sparse-evidence fixtures (enforced
  by the property-based harness).
- Every MCP tool is read-only and idempotent and cache-aware.
- Every public surface has a stability tag documented in
  `docs/stability.md`.

Anything that doesn't move one of these metrics is a nice-to-have
for post-1.0.

## Portfolio / subsidiary detection — genuinely hard, post-1.0 only

Single-domain passive lookups can't reliably detect portfolio or
subsidiary structure — a parent-company landing page with no MX,
no CT-visible subdomains, and no shared breadcrumbs looks identical
to a parked apex. Three avenues worth exploring after 1.0, all
passive and zero-creds, none of them blocking 1.0:

1. **CT-organization search.** `crt.sh` supports searching certs
   by subject `O=` field. On a domain where a cert exposes the
   organization name (e.g. *"Balcan Innovations Inc."*), a
   follow-up CT query can surface every other cert issued to
   the same organization — a real portfolio-discovery signal.
   Risks: crt.sh is flaky, org-name matching is noisy on
   common names, and not every cert has a meaningful `O=`
   (LE certs don't). Worth prototyping post-1.0 and evaluating
   against a real portfolio corpus.

2. **Cross-batch tenant display-name clustering.** The existing
   `cluster_verification_tokens` infrastructure can be extended
   with a sibling that matches M365 tenant display names across
   batch entries. If `balcan.com` has tenant display name "Balcan
   Innovations Inc." and `balcaninnovations.com` matches that
   substring, they are almost certainly operated by the same
   entity. Low risk, uses data we already collect.

3. **BIMI VMC legal-name clustering.** BIMI VMCs carry
   strictly-verified legal organization names. In a batch run,
   matching those names across entries is the strongest passive
   signal available for corporate-ownership clustering. Low
   false-positive rate. Low coverage because BIMI adoption is
   rare outside large brands.

The batch workflow is also the honest answer in recon's output —
the sparse-signal observation now explicitly points users at
`recon batch` and `recon chain` when the panel suggests a
portfolio / holding-company apex is a plausible reading.

## Post-1.0 ideas (not commitments)

Any of these could turn into a minor release. None of them should
block 1.0. The ordering here is rough — real prioritization happens
when there's actual usage data to point at.

- **NetworkX property-graph core** as the single synthesis
  structure. Good refactor, not urgent until the current dataclass
  pipeline starts buckling.
- **Counterfactual hardening simulation with full provenance DAG.**
  Valuable for red-team and acquisition due diligence. Keep
  read-only on cached data.
- **Temporal evidence from CT metadata.** Use the `not_before` /
  `not_after` fields both CT providers already return to surface
  "legacy configuration residue" observations.
- **Feedback-driven posterior tuning.** Opt-in local
  `~/.recon/feedback/` files that downweight specific
  source/fingerprint combinations that have produced false
  positives on the user's targets. Never leaves the local machine.
- **OIDC federation branding metadata** if Microsoft ever exposes
  it on the public discovery endpoint. As of now it doesn't.
- **CT subdomain temporal view** — time-bounded related-domain
  inference for "what was public at time T".
- **Dynamic agent-driven fingerprint injection via MCP.** The
  ephemeral fingerprint tools already cover most of this. Only
  worth expanding if a specific workflow demands it.

## Intentionally not doing

**Hard no.** Any active scanning or probing. Paid APIs. Credentialed
access. Bundled ML models, GloVe/fastText/transformer weights,
paid embedding services. Aggregated local databases. Bundled
ASN / GeoIP data. A plugin system that runs user code.

**Not this tool.** HTML output, web dashboard, `recon serve`,
interactive REPL, STIX2 / Maltego exports, Pydantic models,
Prometheus metrics, SBOM / signed releases / Sigstore attestations,
JSONL streaming, formal machine-validated JSON Schema files,
llms.txt, A2A cards. recon is a CLI plus an MCP server; pipe
`--json` into whatever format or tool you need. If you want a
rendered graph, pipe the node-link JSON into Mermaid or Cytoscape.

**Design choices that stay.**

- No confident "maturity" or "zero-trust" verdicts on sparse data.
  The same evidence fits deliberate hardening and a dormant /
  parked / small-shop target. Positive observations stay hedged
  and two-sided unless `--confidence-mode strict` is set AND the
  density threshold is met.
- No offensive guidance or takeover hints. Observable facts in
  neutral language only.
- No generic subdomain service-name matching
  (`n8n.*`, `automation.*`, `grafana.*`). Too noisy. Verification
  TXT records and CNAME delegations are more reliable.
- No timeline narrative generation. Delta mode and temporal
  evidence surface raw changes; synthesising them into a story is
  the user's or agent's job.
- No confident acquisition or ownership verdicts from shared
  tokens, shared branding, or shared Graph hosts — hedged
  "possible relationship (observed)" only.
- No posture / exposure / insights layer ever triggers a new
  network call. Synthesis runs on cached evidence only.

## Clarification on the JSON stability contract

"No formal machine-validated JSON Schema file" does not mean "no
stable contract". At 1.0 the commitment is the documented shapes
in `docs/schema.md` and the conformance tests that assert them.
That is enough for a consumer to write a parser that will not
break on a patch release, without committing recon to generating
and maintaining a formal JSON Schema artifact that has to be
versioned and published alongside every release.
