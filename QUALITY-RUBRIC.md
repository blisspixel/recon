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
