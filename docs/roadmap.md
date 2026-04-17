# Roadmap

recon is a passive domain-intelligence CLI and MCP server. This
roadmap tracks the path from v0.10 to 1.0. Shipped work lives in
[CHANGELOG.md](../CHANGELOG.md).

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

## Version plan

```
v0.9.3 (shipped) → v0.9.4 (shipped) → v0.10 (shipped) → v0.10.1 → v0.10.2 → v0.11 → v1.0
```

Each release is independently shippable. The sequence is priority
order — if something slips, it pushes right, it doesn't block
what came before it.

| Release  | Theme                        | Key deliverable                                               |
|----------|------------------------------|---------------------------------------------------------------|
| v0.9.4   | Toolchain & release hygiene  | CI pipeline, pre-commit, MCP optional extra, SECURITY.md      |
| v0.10    | CT resilience + UX overhaul  | CT cache fallback, insight curation, provider accuracy        |
| v0.10.1  | Provider accuracy + UX depth | Primary email detection, category rethink, DKIM expansion     |
| v0.10.2  | Passive coverage depth       | Chained fingerprints, deeper subdomain DNS, delta mode        |
| v0.11    | Community & confidence       | Fingerprint contribution pipeline + `--confidence-mode strict` |
| v1.0     | Stability commitment         | Frozen surfaces, security/limitations docs, release process   |

---

### v0.9.4 — Toolchain & release hygiene (shipped 2026-04-16)

Infrastructure-only release. No feature changes.

- ~~CI pipeline (GitHub Actions)~~ — Ruff → Pyright → pytest +
  coverage gate (80%) → pip-audit. Required on every PR.
- ~~pre-commit hooks~~ — `.pre-commit-config.yaml` with Ruff +
  Pyright.
- ~~MCP as optional extra~~ — `pip install recon-tool[mcp]`. Core
  install no longer pulls in the MCP dependency tree.
- ~~pip-audit in CI~~ — dependency vulnerability scanning on every
  PR and release build.
- ~~Root `SECURITY.md`~~ — vulnerability reporting policy.
- ~~Trusted Publisher on PyPI~~ — OIDC-based publishing (already in
  place since v0.9.3, formalized).
- ~~uv migration~~ — `uv.lock` for reproducible builds, CI uses
  `uv sync`.

---

### v0.10 — CT source resilience (shipped 2026-04-16)

- ~~Per-domain CT cache~~ — `~/.recon/ct-cache/{domain}.json`,
  seven-day TTL, one file per domain. Successful provider queries
  auto-populate.
- ~~Cache fallback chain~~ — crt.sh → CertSpotter → per-domain
  cache. On total provider outage, returns cached subdomain set
  with explicit "from local cache, N days old" annotation.
- ~~Cache CLI~~ — `recon cache show [domain]` and
  `recon cache clear [--all]`.
- ~~Cache age in panel~~ — info-tone note distinguishes live
  fallback from cache fallback.
- Third zero-creds CT provider deferred — all candidates
  (Merklemap, Google CT, certificatetransparency.dev) now require
  authentication. The `CertIntelProvider` protocol is ready when
  a viable zero-creds provider surfaces.
- ~~UX overhaul~~ — aggressive insight curation (drop restatements
  of Services/Provider), cap at 5 in default mode, strip protocol
  config from Email row (score covers it), strip provider-line
  services from Email (no duplication), suppress info-tone CT notes,
  remove decorative color (bold-only section headers).
- ~~Provider accuracy~~ — exchange-onprem + M365 tenant now
  correctly renders as "Microsoft 365 via [gateway]" instead of
  "Exchange Server (on-prem / hybrid)". On-prem only leads when
  no M365 tenant is found.
- ~~Bundled AI inference~~ — M365 → Microsoft Copilot (likely),
  Google Workspace → Google Gemini (likely) in Services > AI.

---

### v0.10.1 — Provider accuracy + UX depth

The v0.10 UX pass exposed deeper issues in provider classification
and category architecture. This release addresses the structural
problems that need careful work with test coverage.

#### Primary email detection overhaul

*Files:* `formatter.py` (`detect_provider`), `merger.py`,
`models.py`, `sources/dns.py`.

The "everyone has both providers" problem: most companies have
ONE primary email platform, but the tool shows dual because
a dormant account registration (OIDC discovery responds, TXT
token exists) looks identical to an active platform. The fix:

- **Evidence-weighted provider classification.** Distinguish
  "confirmed email platform" (MX points here, or MX → gateway +
  DKIM for this provider) from "account registered" (tenant ID
  exists but no email routing evidence). Show confirmed platforms
  as primary; show account-only detections as "(account)" only
  in `--full`.
- **Gateway → backend inference.** When MX points to a known
  gateway (Proofpoint, Trend Micro, Mimecast, Barracuda,
  Symantec) AND M365 DKIM selectors are found, infer M365 as
  the backend. Same for Google Workspace DKIM behind a gateway.
  This eliminates "Exchange Server (on-prem / hybrid)" false
  positives for cloud M365 behind a gateway.

#### DKIM selector expansion

*Files:* `sources/dns.py`.

The email security score undercounts DKIM because it only checks
common selector names (`selector1`, `selector2`, `google`). Large
enterprises use non-standard selectors. Expand the selector
probing set with enterprise-common names (`s1`, `s2`, `dkim`,
`mail`, `k1`, `k2`, `default`) to reduce false "No DKIM"
findings on Fortune 500 targets.

#### Service category rethink

*Files:* `formatter.py` (`_SERVICE_CATEGORIES_ORDER`,
`_CATEGORY_BY_SLUG`).

- Rename and reorder: Identity → Cloud → Security → AI →
  Collaboration → Email → Other.
- Move misclassified services: Intune → Identity (not Other),
  Microsoft Teams → Collaboration (not Other).
- Consider splitting "Other" into "Business Apps" (Salesforce,
  ServiceNow, DocuSign) vs true Other.

#### Conditional insights

*Files:* `formatter.py`, `insights.py`.

Not every domain needs the same insight set. The email security
score should render differently based on what it means for the
target:

- Fortune 500 / enterprise: 3/5 with missing DKIM is notable
  → show it.
- Small org with DMARC + DKIM: 2/5 is normal → less emphasis.
- No email infrastructure at all: don't show a score (currently
  handled, keep it).

---

### v0.10.2 — Passive coverage depth

The v0.10.1 work fixed provider accuracy and category hygiene.
v0.10.2 goes after detection coverage — still 100% passive, still
zero credentials, still per-domain storage. Three targeted
expansions that stay inside the project invariants:

#### Chained fingerprint patterns

*Files:* `recon_tool/fingerprints.py`, `data/fingerprints.yaml`.

Today each fingerprint is a single regex against one DNS record
type. Real SaaS signatures often span records: Service X publishes
a TXT verification token AND needs a specific CNAME AND uses a
particular MX. Single-record fingerprints miss correlated patterns
and also produce false positives on domains that happen to have
one matching record.

- *Change:* Add an optional `match_mode: all` + multi-detection
  structure to the fingerprint YAML schema. When present, all
  listed detections (possibly across record types) must match
  before the slug fires. Partially already supported via
  `_matched_fp_detections` in `_DetectionCtx` — formalize and
  document for contributors.
- *Done when:* At least 20 fingerprints use chained patterns,
  false-positive rate on the hardened corpus is measurably
  lower, and the YAML schema doc describes the chaining syntax.

#### Deeper DNS enrichment on CT-discovered subdomains

*Files:* `resolver.py`, `sources/dns.py` (`lightweight_subdomain_lookup`).

Today CT-discovered subdomains get a lightweight CNAME+TXT
lookup. Deeper passive enrichment — MX check, DKIM selector
probe on the subdomain, SPF parse — would catch SaaS that
publish verification records on non-apex names (common for
staging / regional / tenant-specific deployments).

- *Change:* Add a middle-tier `medium_subdomain_lookup` that
  adds MX + `selector1/2/google._domainkey` TXT probes on top
  of CNAME+TXT. Cap at high-signal subdomains only (auth.*,
  login.*, sso.*, api.*) so we don't fan out the DNS budget.
- *Done when:* Subdomain-only fingerprint hits exist for at
  least three SaaS that currently go undetected when their
  verification lives on a subdomain only.

#### Per-domain delta mode

*Files:* new `recon_tool/delta.py` (existing file),
`recon_tool/ct_cache.py`, `cli.py`.

Stateless today: every run is fresh. But CT data is already
cached per-domain. A `recon delta contoso.com` that compares
the current lookup against the cached CT subdomain set +
cached TenantInfo surfaces what changed — new subdomains,
new services, removed DMARC, changed auth type. Uses only
already-cached data; still per-domain JSON; no aggregated
store.

- *Change:* Extend the existing delta module (`delta.py`
  already exists) to read the cached CT entry and previous
  TenantInfo cache, diff against the current run, emit a
  `Changes since {cached_at}` block.
- *Done when:* `recon delta <domain>` returns a structured
  diff (services added/removed, subdomains added/removed,
  posture-score delta). Batch mode can use the same machinery
  to show churn across a peer set.

---

### v0.11 — Community fingerprints + confidence mode

Two features that both gate on 1.0 but are independent of each
other. Ship them together or separately within v0.11.x — ordering
between them doesn't matter.

#### Community fingerprint pipeline

The fingerprint database is 227 entries maintained by one person.
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

#### `--confidence-mode strict`

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

#### Bayesian evidence fusion (experimental, not blocking 1.0)

The probabilistic fusion layer. Good idea, but not a 1.0 blocker.
Ship it as **experimental** in v0.11 if the math is ready;
otherwise push to post-1.0.

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

---

### v1.0 — Stability commitment

Ship 1.0 when the items above are stable, not when every idea on
this page is done. The 1.0 commitment is small and concrete:

1. **Frozen public surfaces.** CLI flags, `--json` output field
   names and types, MCP tool names and parameter shapes, YAML
   schemas for fingerprints / signals / profiles, config file
   locations. Each surface tagged **stable** or **experimental**
   in a single `docs/stability.md`. Breaking any stable surface
   requires a 2.0 and a deprecation window.
2. **SemVer + Python support policy.** Documented. Python version
   support window matches CPython's own N-2 policy.
3. **Security threat model** in `docs/security.md`. One page
   covering trust boundaries, attack surface, mitigations,
   out-of-scope. (The root `SECURITY.md` for vulnerability
   reporting ships in v0.9.4 — this is the deeper document.)
4. **Known limitations** in `docs/limitations.md`. What the tool
   doesn't see, what it underclaims on, and when to reach for
   something else.
5. **Release process.** Documented checklist. GitHub Actions handles
   the build-test-publish pipeline (established in v0.9.4);
   `scripts/release.py` handles the human steps — version bump,
   changelog finalization, tag creation — with confirmation prompts
   at each destructive step. Both halves documented in one place.
6. **Community fingerprint pipeline** (from v0.11).
7. **CT resilience + cache visibility** (from v0.10).
8. **`--confidence-mode strict`** (from v0.11).

**Metrics that matter for 1.0:**
- >=80% signal coverage on the hardened enterprise test corpus.
- Zero unhedged assertions on sparse-evidence fixtures (enforced
  by the property-based harness).
- Every MCP tool is read-only, idempotent, and cache-aware.
- Every public surface has a stability tag in `docs/stability.md`.
- CI pipeline enforced on every PR (lint, types, tests, coverage,
  audit).

Anything that doesn't move one of these metrics is a nice-to-have
for post-1.0.

---

## Large-file refactoring (opportunistic, not blocking any release)

Three files carry disproportionate maintenance burden:
`formatter.py` (2,635 lines), `server.py` (1,876 lines), and
`cli.py` (1,225 lines). These are where future changes will get
slower, harder to review, and more bug-prone.

Refactoring them into submodules (e.g., `formatter/` with
`panel.py`, `json.py`, `markdown.py`; `server/` with per-tool
modules) is the right move, but it's not gated on any release.
Do it opportunistically when a feature change in one of these
files makes the split natural, not as a standalone refactoring
milestone. The priority order (correctness → reliability →
explainability → composability → new features) means refactoring
waits until it unblocks something else.

---

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
Prometheus metrics, SBOM / Sigstore attestations, JSONL streaming,
formal machine-validated JSON Schema files, llms.txt, A2A cards,
Homebrew tap, Docker image. recon is a CLI plus an MCP server;
pipe `--json` into whatever format or tool you need. If you want a
rendered graph, pipe the node-link JSON into Mermaid or Cytoscape.

Note: **Trusted Publisher on PyPI is not Sigstore attestation.**
Trusted Publisher is OIDC-based publish-path integrity — it
verifies *who published*, not *what was published*. It's planned
for v0.9.4. Sigstore attestation (artifact signing, provenance
chains, SBOM) is a different system and remains out of scope.

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
