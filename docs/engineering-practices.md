# Engineering practices

The bar for this codebase is simple to state and hard to clear: **code any human
or AI could admire** — coherent architecture, one obvious way to do each thing,
small reviewable units, no dead corners, and every promise backed by a gate, not
a hope. This file is the standard we hold ourselves (and any AI working here) to,
and an honest scorecard of where we meet it and where we don't yet.

It is grounded in a 2026 review of current best practices (Ruff/Astral docs,
PyPA, clig.dev, PEP 8/257, the Python devguide, GitClear/DORA/Thoughtworks on
AI-code quality, MADR for ADRs); dated sources live in the commit that added
this file. Standards drift, so the currency mechanisms in
[§8](#8-keeping-deps-and-standards-current) are part of the practice, not an
afterthought — an AI assistant in particular has no sense of what changed in the
last six months unless the repo's automation tells it.

## 1. The one command before you push

`python scripts/check.py` runs the **exact** CI gate locally — ruff, pyright
over `recon_tool/ tests/` (the same scope CI uses), the coverage-gated test run,
and the catalog/label/file-size checks. "Green here ⇒ green in CI." Use
`--fast` to skip the test run for rapid iteration; never push on `--fast` alone.

This exists because local checks that were *narrower* than CI (pyright on
`recon_tool/` only) let test-file type errors reach a red CI twice. Parity is the
fix, encoded once. The pre-commit hooks mirror the same scopes.

## 2. Architecture and organization

- **Layering.** Pure logic (inference, calibration, scoring, parsing) is
  separable from IO (DNS/CT/HTTP sources) and from the user-facing shell (CLI
  rendering, MCP serialization). The core returns values and raises typed
  errors; `print`/`sys.exit`/network live at the edges. This is what makes the
  core exhaustively unit-testable without mocks.
- **No surprising global mutable state.** Constants are fine; mutable singletons
  (the Rich consoles, the color override) carry an explicit test seam
  (`set_console`/`set_err_console`/`set_color_override`) and are reset between
  tests. New shared state should be injected, not module-global.
- **File and function size (enforced).** Functions: complexity ≤ 10 (`C901`,
  enforced). Modules: new files cap at **1000 lines** (the pylint `C0302`
  convention; Ruff has no native file-length rule, so `scripts/check_file_size.py`
  is our ratchet). The modules that predate the guard are baselined as ceilings
  that may only *shrink* — see the decomposition track in
  [roadmap.md](roadmap.md). Goal state: every baseline entry gone, every module
  under the cap.
- **`pyproject.toml` is flat-layout, deliberately.** src-layout is the default
  recommendation for *new* packages; recon is an established package with a
  stable import path and a locked schema, so the churn of migrating isn't worth
  it. Recorded as a decision, not an oversight (see `docs/adr/`).
- **Significant or hard-to-reverse decisions get an ADR** (`docs/adr/`), one
  decision per record, immutable once accepted. The invariants, the MNAR absence
  rule, the schema lock, and the no-numpy choice are recorded there so the
  rationale outlives memory.

## 3. Readability and consistency

- **One way to do each thing.** A single canonical helper per task; deduplicate
  rather than grow a second sloppy path. Duplicated logic is the single most
  common AI-code regression — prefer one tested helper over three plausible
  copies. (Balance against over-abstraction: duplicate until the third instance,
  then abstract.)
- **Naming.** PEP 8 (`snake_case`, `CapWords`, `ALL_CAPS`, `_private`). CLI
  subcommands are **noun-verb** (`cache show`, `fingerprints list`) and a verb
  means the same thing across resources — internal consistency is the binding
  rule. Standard flags (`--json`, `-h/--help`, `-q`, `--force`) keep their
  conventional meaning.
- **Docstrings** (PEP 257, imperative summary) on public surfaces; comments
  explain **why**, not what.
- **Types** on public APIs, modern `X | None`, checked with pyright `strict`;
  `py.typed` ships. Validate untrusted input at the edge (CLI args, DNS/CT/HTTP
  responses); trust static types internally.
- **Imports** absolute, ordered by ruff isort, no wildcard imports (except a
  package re-export). `# noqa` is always rule-specific and justified; `RUF100`
  removes stale ones.

## 4. AI-generated-code discipline

The repo is built and extended partly by AI, which has well-documented failure
modes (2026 research): duplication / reinvented helpers, drifting from project
conventions toward training-data defaults, plausible-but-wrong logic, security
gaps, oversized change sets, and — worst — being merged without real review. The
mitigations are mechanical and non-negotiable:

- **The gates catch convention drift and hallucinated APIs:** ruff + strict
  pyright + the parity gate. An AI change that invents an API or breaks a pattern
  fails before merge.
- **Small, reviewable units.** One story per commit; the file/function-size caps
  keep changes legible.
- **Don't merge what you can't explain.** "A computer can never be held
  accountable." No change lands because a tool said LGTM; a human (or the author)
  must be able to explain why it's correct and what failure modes it handles —
  not just the happy path.
- **Verify, don't assume.** Watch CI to an authoritative conclusion (a watcher's
  exit code is not proof; read the run's `conclusion`). This was a real lesson —
  an assumed-green run was actually still in progress.
- **Scale gates with volume.** More generated code ⇒ more verification, not less.

## 5. Testing and coverage

- **Branch coverage**, gated (`--cov-branch --cov-fail-under=82`). Coverage is a
  floor, not the goal — 100% is explicitly not the target; pair it with quality
  signals.
- **Mutation testing** (cosmic-ray, blocking gate over the inference core) proves
  the tests actually *detect* faults, not just execute lines.
- **Property-based tests** (Hypothesis) for invariants, round-trips, and parsers;
  **golden/snapshot tests** for rendered output (reviewed on diff, never
  blind-updated, redacted for determinism).
- **Differential verification** of the inference core against an independent
  full-joint reference. Honest-evaluation discipline (CAL1–CAL14): consistency
  vs calibration named precisely, never overclaimed.

## 6. Security and supply chain

Already at a high bar, kept there: ruff `S` rules, `pip-audit`, secret scanning,
SBOM (CycloneDX), SLSA build provenance, reproducible builds
(`SOURCE_DATE_EPOCH`), PyPI Trusted Publishing (OIDC, no long-lived token) with
PEP 740 attestations. Returned external content is treated as untrusted data,
not instructions (the MCP data-not-instructions boundary), and control bytes are
stripped at every source-derived sink.

## 7. Releases

`scripts/release.py` enforces the pre-release checklist; the tagged build
publishes via Trusted Publishing. Per-release, refresh the Homebrew formula
(`scripts/update_homebrew_formula.py`); the `pipx`/`uv`/`pip` paths and
`recon update` need no per-release action (they resolve PyPI's latest).

## 8. Keeping deps and standards current

Automation, not memory, keeps things fresh — the direct mitigation for an
assistant's lack of time-sense:

- **Dependabot** over `pip`, `github-actions`, and `pre-commit` ecosystems
  (weekly, grouped, majors split for review) so runtime deps, pinned actions, and
  pinned hook revisions don't silently rot.
- **The parity gate and pinned tool versions** keep the local and CI toolchains
  identical; `pre-commit autoupdate` (via the Dependabot pre-commit ecosystem)
  keeps the hooks current.

## Honest scorecard (2026)

What we already do well, and the named open items — no pretending.

| Area | Status | Note |
|---|---|---|
| Single toolchain (ruff lint+format), strict pyright, `py.typed` | ✅ | |
| Branch coverage gate + mutation + Hypothesis + golden + differential | ✅ | among the strongest parts |
| Security + supply chain (pip-audit, ruff-S, SBOM, SLSA, Trusted Publishing, PEP 740) | ✅ | top-tier |
| Dependency + standards currency (Dependabot pip/actions/pre-commit) | ✅ | pre-commit ecosystem added 2026 |
| CI↔local parity (`scripts/check.py`), file-size ratchet | ✅ | closes the CI-red root cause |
| ADRs for load-bearing decisions | ✅ (initial set) | extend as decisions are made |
| Noun-verb CLI consistency, `--plain`/`--json`, stdout/stderr discipline | ✅ | |
| **God-file decomposition** (formatter/cli/exposure/merger/dns/bayesian/server) | ✅ | complete 2026-06-14; every module under the 1000-line cap except formatter's cohesive panel core (~2160, kept whole by design) |
| **`PLR09xx` function-size rules** (statements/branches/args/returns) | ⏳ partial | only `C901` today; tighten gradually |
| **Per-PR diff coverage** | ⏳ partial | total `fail_under` only; add diff-cover |

The open items are tracked, ratcheted, or scheduled — none is a silent gap.
