# Engineering practices

The bar for this codebase is simple to state and hard to clear: **code any human
or AI could admire**: coherent architecture, one obvious way to do each thing,
small reviewable units, no dead corners, and every promise backed by a gate, not
a hope. This file is the standard we hold ourselves (and any AI working here) to,
and an honest scorecard of where we meet it and where we don't yet.

It is grounded in a 2026 review of current best practices (Ruff/Astral docs,
PyPA, clig.dev, PEP 8/257, the Python devguide, GitClear/DORA/Thoughtworks on
AI-code quality, MADR for ADRs); dated sources live in the commit that added
this file. Standards drift, so the currency mechanisms in
[§8](#8-keeping-deps-and-standards-current) are part of the practice, not an
afterthought. An AI assistant in particular has no sense of what changed in the
last six months unless the repo's automation tells it.

## 1. The one command before you push

`uv run python scripts/check.py` runs the **exact** CI gate locally: ruff, pyright
over `src/recon_tool/ tests/` (the same scope CI uses), the coverage-gated test run,
and the catalog/label/file-size checks. Green here means green in CI. Use
`--fast` to skip the test run for rapid iteration; never push on `--fast` alone.
Before pushing a local stack, `uv run python scripts/release_readiness.py` also
checks every `origin/main..HEAD` commit message for attribution markers, em
dashes, and pictographic symbols.

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
  that may only *shrink*. See the decomposition track in
  [roadmap.md](roadmap.md). Goal state: every baseline entry gone, every module
  under the cap.
- **`src/` layout is the package layout.** Source files live under
  `src/recon_tool/`; the public import name remains `recon_tool`. This keeps
  tests honest about installed-package behavior and avoids repo-root import
  shadowing. ADR-0006 supersedes the previous flat-layout decision.
- **Significant or hard-to-reverse decisions get an ADR** (`docs/adr/`), one
  decision per record, immutable once accepted. The invariants, the MNAR absence
  rule, the schema lock, and the no-numpy choice are recorded there so the
  rationale outlives memory.

## 3. Readability and consistency

- **One way to do each thing.** A single canonical helper per task; deduplicate
  rather than grow a second sloppy path. Duplicated logic is the single most
  common AI-code regression. Prefer one tested helper over three plausible
  copies. (Balance against over-abstraction: duplicate until the third instance,
  then abstract.)
- **Naming.** PEP 8 (`snake_case`, `CapWords`, `ALL_CAPS`, `_private`). CLI
  subcommands are **noun-verb** (`cache show`, `fingerprints list`) and a verb
  means the same thing across resources. Internal consistency is the binding
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
gaps, oversized change sets, and, worst, being merged without real review. The
mitigations are mechanical and non-negotiable:

- **The gates catch convention drift and hallucinated APIs:** ruff + strict
  pyright + the parity gate. An AI change that invents an API or breaks a pattern
  fails before merge.
- **Small, reviewable units.** One story per commit; the file/function-size caps
  keep changes legible.
- **Don't merge what you can't explain.** "A computer can never be held
  accountable." No change lands because a tool said LGTM; a human (or the author)
  must be able to explain why it's correct and what failure modes it handles,
  not just the happy path.
- **Verify, don't assume.** Watch CI to an authoritative conclusion (a watcher's
  exit code is not proof; read the run's `conclusion`). This was a real lesson:
  an assumed-green run was actually still in progress.
- **Scale gates with volume.** More generated code requires more verification, not less.
- **Only loop repeatable work with a hard verifier.** A maintainer automation
  loop is worth adding only when the task repeats, success is checked by a gate,
  token and runtime cost are bounded, and the loop can read logs and run the
  same tools a maintainer would. The minimum shape is one trigger, one scoped
  runbook or skill, one state file, and one hard gate. If most proposed changes
  need manual rescue, stop the loop and use a smaller manual workflow.

## 5. Testing and coverage

- **Branch coverage**, gated (`--cov-branch --cov-fail-under=82`). Coverage is a
  floor, not the goal. 100% is explicitly not the target; pair it with quality
  signals.
- **Diff coverage**, advisory and local-first:
  `scripts/diff_coverage.py` reads Coverage.py JSON plus a unified diff and
  reports coverage only for changed executable Python lines. It is not in the
  blocking gate, so documentation-only changes stay cheap.
- **Mutation testing** (cosmic-ray, blocking gate over the inference core) proves
  the tests actually *detect* faults, not just execute lines.
- **Property-based tests** (Hypothesis) for invariants, round-trips, and parsers;
  **coverage-guided PR fuzzing** (ClusterFuzzLite + Atheris) for parser and
  serialization boundaries; **golden/snapshot tests** for rendered output
  (reviewed on diff, never blind-updated, redacted for determinism).
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

Automation, not memory, keeps things fresh. It is the direct mitigation for an
assistant's lack of time-sense:

- **Dependabot** over the `uv` and `github-actions` ecosystems, monthly and
  grouped with a low PR limit, so runtime dependencies and workflow actions do
  not silently rot.
- **Security alerts interrupt normal roadmap work.** Inspect the advisory and
  dependency path, update the lock or constraint to the patched version, and run
  `pip-audit` before resuming feature or docs work.
- **The parity gate and pinned tool versions** keep the local and CI toolchains
  identical; `scripts/release_readiness.py` catches release and docs drift before
  remote CI is the first signal.

## Honest scorecard (2026)

What we already do well, and the named open items, with no pretending.

| Area | Status | Note |
|---|---|---|
| Single toolchain (ruff lint+format), strict pyright, `py.typed` | In place | |
| Branch coverage gate + mutation + Hypothesis + ClusterFuzzLite + golden + differential | In place | Among the strongest parts |
| Security + supply chain (pip-audit, ruff-S, CodeQL, SBOM, build provenance, Trusted Publishing, PEP 740) | In place | Scorecard now detects SAST, dependency-update tooling, and least-privilege workflow tokens; ClusterFuzzLite is wired for the next public scan |
| Dependency + standards currency (Dependabot uv/actions) | In place | Monthly, grouped, low-noise updates; pip build commands use hash-pinned requirements and source-path loading where Scorecard can inspect them |
| CI/local parity (`scripts/check.py`), release readiness, file-size ratchet | In place | Closes the CI-red and docs-drift root causes |
| ADRs for load-bearing decisions | In place initially | Extend as decisions are made |
| Noun-verb CLI consistency, `--plain`/`--json`, stdout/stderr discipline | In place | |
| **God-file decomposition** (formatter/cli/exposure/merger/dns/bayesian/server) | In place | Every module under the 1000-line cap except formatter's cohesive panel core (~2160, kept whole by design) |
| **`PLR09xx` function-size rules** (statements/branches/args/returns) | Ratcheted | `scripts/check_plr_ratchet.py` blocks new debt while existing violations are paid down |
| **Schema generation path** | Guarded | `scripts/check_schema_sources.py` and nested `$defs` tests block untraced schema drift while the full generator remains open |
| **Per-PR diff coverage** | Advisory | `scripts/diff_coverage.py` reports changed-line coverage from local Coverage.py JSON without making doc-only changes painful |

The open items are tracked, ratcheted, or explicitly deferred. None is a silent gap.
