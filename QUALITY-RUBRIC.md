# Quality Rubric

Maker-checker scoring rubric for every change in this checkout. It does not
replace the canonical standard, [docs/engineering-practices.md](docs/engineering-practices.md);
it is the scorecard that standard is applied through. A change ships only when
all six categories score 5/5. The single command that proves most of this is
`uv run python scripts/check.py` (the exact CI gate); the rest is human review.

## Scale

- **5 Strong:** exactly what a ruthless principal engineer would merge.
- **4 Minor:** one small, named nit; fix before commit.
- **3 or below:** do not ship; rework.

## Categories

1. **Correctness.** Behaviour matches intent on the happy path and the failure
   path. New logic is covered by tests, including the boundary and the negative
   case. Deterministic where the repo requires it (byte-identical output, no
   `Date.now`/`Math.random` in the core). Gate: pytest + branch coverage,
   mutation gate, differential verification.

2. **Security and supply chain.** Untrusted input (DNS, CT, HTTP, MCP) is
   treated as data, not instructions; control bytes stripped at sinks; parsers
   bounded. No new dependency, credential, paid API, or active probe. Gate:
   ruff-S, pip-audit, ClusterFuzzLite, pinned workflows, no-real-data review.

3. **Performance.** No needless work on hot paths (`detect_provider`,
   `_curate_insights`, DNS batching). No accidental quadratic behaviour or
   per-call recompute. Network respects the documented concurrency and CT caps.

4. **Readability.** Reads like the surrounding code: PEP 8, modern typing,
   imperative docstrings on public surfaces, comments explain why not what. No
   narration, no dead corners. One obvious way to do each thing.

5. **Maintainability.** Small reviewable unit, one story per commit. No
   duplicated logic (one tested helper over copies), no single-use abstraction,
   no defensive checks inside validated boundaries. Functions under the
   complexity cap, modules under the size cap.

6. **Sustainability and invariants.** Stays inside the box: passive, zero-creds,
   no bundled ML/DB, no user-code plugins, output hedged and provenance-backed.
   Honours the deepen-not-expand phase. Detection or CPT changes are validated
   against the corpus (aggregate-only) before shipping; stable surfaces keep
   their contract. Aligns with [docs/agentic-balance.md](docs/agentic-balance.md).

## House rules (non-negotiable, all categories)

No AI attribution, no em dashes, no emojis, no time estimates in the roadmap.
Track external spend explicitly; default 0 USD, lifetime cap 5 USD. Public
artifacts never carry real apexes, organization names, tenant IDs, per-domain
findings, or unsuppressed small strata.

## Current Alignment Snapshot

Cycle 6 scope: live documentation refresh for the README, docs index, roadmap,
getting-started guide, and plain-language model overview.

Maker-checker score:

| Category | Score | Evidence |
|---|---:|---|
| Correctness | 5/5 | README readiness anchors, roadmap version status, ADR-0007 references, markdown links, automation docs, and generated surface checks passed. |
| Security and supply chain | 5/5 | Docs only; no dependency, credential, paid API, active probe, or runtime behavior change. |
| Performance | 5/5 | Documentation changes do not affect lookup, batch, MCP, or validation hot paths. |
| Readability | 5/5 | README is a concise front door; install and model detail moved to focused docs; roadmap now states current work and invariants directly. |
| Maintainability | 5/5 | Removes roadmap bloat and README duplication while preserving required anchors and links to canonical references. |
| Sustainability and invariants | 5/5 | Keeps deepen-not-expand framing, no-real-data policy, passive boundary, and surface-inventory non-contract decision visible. |

External spend: 0 USD.

Cycle 5 scope: C3 CT partial-session recovery, batch timeout plumbing, and
maintainer-local scan finalization.

Maker-checker score:

| Category | Score | Evidence |
|---|---:|---|
| Correctness | 5/5 | `recon batch --timeout` is passed to `resolve_tenant`; `scan.py` finalizes completed, partial, and recovered NDJSON runs; malformed trailing partial lines are ignored in record counts. |
| Security and supply chain | 5/5 | No dependency, credential, paid API, or new active probe; private corpus artifacts remain gitignored and the public memo is aggregate-only. |
| Performance | 5/5 | Large-result counters stream NDJSON; controlled `--max-runtime` avoids unbounded corpus sessions; process-tree termination prevents orphaned batch work. |
| Readability | 5/5 | Scan orchestration is split into explicit batch, finalization, counting, and recovery helpers with direct CLI flags. |
| Maintainability | 5/5 | Shared finalizer removes duplicated post-batch logic and tests cover timeout wiring, partial recovery, malformed tails, and generated surface drift. |
| Sustainability and invariants | 5/5 | Keeps C3 as a maintainer-local, partial, aggregate-only validation track and does not overclaim CT coverage as Bayesian calibration. |

Cycle health: 5/5 | Simplicity: 5/5 | Est. spend: $0 | New skill distilled: none

External spend: 0 USD.

Cycle 1 scope: boundary-aware hostname matching in Google identity routing,
plus a shared suffix helper used by Google CSE IdP naming, Google identity IdP
naming, and Exchange Online DKIM attribution.

Maker-checker score:

| Category | Score | Evidence |
|---|---:|---|
| Correctness | 5/5 | Focused positive and negative tests cover exact suffix, dotted suffix, lookalike hosts, and path/query-only vendor strings. |
| Security and supply chain | 5/5 | Uses parsed URL host plus explicit suffix boundary; adds no dependency, credential, API, or active probe. |
| Performance | 5/5 | Constant-time string normalization and suffix checks on existing hot paths; no extra network or repeated catalog work. |
| Readability | 5/5 | One small helper with direct tests; detector code reads in terms of the domain concept it needs. |
| Maintainability | 5/5 | Removes duplicated local suffix predicates instead of adding another one; no surface or schema churn. |
| Sustainability and invariants | 5/5 | Patch-level hardening inside the passive deterministic core, aligned with the deepen-not-expand roadmap phase. |

External spend: 0 USD.

Cycle 4 scope: surface-inventory promotion decision and cycle-4 skill distill.

Maker-checker score:

| Category | Score | Evidence |
|---|---:|---|
| Correctness | 5/5 | ADR-0007 records the decision, roadmap and docs link it, and tests pin the accepted status plus promotion gate. |
| Security and supply chain | 5/5 | No runtime behavior, dependency, credential, or network surface change. |
| Performance | 5/5 | Documentation and tests only; generated resource runtime path is unchanged. |
| Readability | 5/5 | Decision separates discovery context from stable contracts and names the promotion preconditions directly. |
| Maintainability | 5/5 | The decision prevents accidental 2.3 compatibility obligations until a consumer proves the smallest stable subset. |
| Sustainability and invariants | 5/5 | Keeps recon in deepen-not-expand mode and preserves stable contracts only where they already exist. |

External spend: 0 USD.

Cycle 3 scope: schema generator drift gate for the top-level JSON contract and
both published schema copies.

Maker-checker score:

| Category | Score | Evidence |
|---|---:|---|
| Correctness | 5/5 | Generator checks required fields, conditional fields, source-map traceability, both schema copies, missing fragments, and stale required fields. |
| Security and supply chain | 5/5 | Pure local script, no network, no dependency, no credential, no runtime behavior change. |
| Performance | 5/5 | Runs in milliseconds inside existing validation jobs and does not affect lookup hot paths. |
| Readability | 5/5 | Small script with one code-owned field list for conditional properties and direct error messages. |
| Maintainability | 5/5 | Uses the existing runtime required-field mirror and schema-source audit rather than duplicating those checks. |
| Sustainability and invariants | 5/5 | Deepens schema trust without expanding the passive collection surface or changing the v2.0 contract. |

External spend: 0 USD.

Cycle 2 scope: 2.2.14 patch release, remote publication verification, and
Homebrew formula refresh from the published PyPI sdist.

Maker-checker score:

| Category | Score | Evidence |
|---|---:|---|
| Correctness | 5/5 | Release notes moved only shipped fixes into 2.2.14, package metadata is consistent, PyPI reports 2.2.14, and the formula pins the matching sdist digest. |
| Security and supply chain | 5/5 | Release workflow produced wheel, sdist, SBOM, and intoto provenance assets; no credentials or paid services were introduced. |
| Performance | 5/5 | Release-only changes do not affect runtime hot paths. |
| Readability | 5/5 | Changelog, roadmap, and formula updates are direct and version-specific. |
| Maintainability | 5/5 | The release used the existing scripted path and preserved the one-line formula bump model. |
| Sustainability and invariants | 5/5 | Patch release ships correctness hardening inside the passive deterministic core with no new stable surface. |

External spend: 0 USD.
