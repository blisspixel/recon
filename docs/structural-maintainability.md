# Structural Maintainability

Status: measured plan, checked 2026-07-14 against recon v2.6.3 at
`3d5218e00e969874dda40956d677e131d392dbf9`.

This plan addresses a specific failure mode of fast, AI-assisted development:
code can become locally tidy while the repository becomes harder to navigate.
The inverse failure is also common. A rule against small files can preserve
god modules that are difficult to review safely. recon will optimize for
cohesion, ownership, dependency direction, and reader effort, not for a target
line count or file count.

## Decision Summary

recon does not have general micro-module sprawl. Most tiny runtime files are
intentional compatibility shims. Ordinary implementation modules are more
often large than small, the source tree is only one package level deep, and
the test suite has very few one-test files.

The measured structural problems are narrower:

1. Twenty-four compatibility shims and several broad re-export facades make it
   harder to find the defining module.
2. Five catch-all test suites group unrelated behavior under historical names
   such as `coverage`, `features`, and `enhanced`.
3. One interface module remains above the file-size ceiling, 15 more runtime
   modules are between 800 and 999 lines, and 67 production function-complexity
   findings remain under ratchet.
4. One test-only source and two maintainer-only helpers ship in the runtime
   package and need explicit contract or packaging decisions.

The response is not a bulk merge or package move. It is a staged cleanup that
first improves ownership maps, then removes proven compatibility or runtime
debt at a SemVer-safe boundary, and only then splits the remaining hotspots
along cohesive responsibilities.

## Repository Evidence

The 2026-07-14 full local code graph is current, high trust, warning-free, and
has no circular import component. Its deterministic integrity sample passes
10 of 10 checks. Literal `importlib.import_module("...")` calls are now
resolved in the local graph, so each compatibility shim has an explicit edge
to its canonical implementation. Computed dynamic imports, framework
registration side effects, reflection, and monkeypatching remain bounded
uncertainty and still require source and test verification.

### Runtime shape

| Measure | Result |
|---|---:|
| Runtime Python modules | 133 |
| Runtime Python lines | 42,043 |
| Compatibility shims | 24 modules, 432 lines |
| Ordinary implementations | 102 modules, 40,040 lines |
| Ordinary implementation median | 286 lines |
| Ordinary implementation p90 | 888 lines |
| Ordinary implementations at or below 50 lines | 4 |
| Ordinary implementations at or below 100 lines | 13 |
| Ordinary implementations above 400 lines | 38 |
| Runtime modules at or above 800 lines | 16 |
| Runtime modules from 800 through 999 lines | 15 |
| Ratcheted production `PLR09xx` findings | 67 |
| Package depth below `recon_tool` | one level maximum |

The compatibility layer is 18.0 percent of runtime Python files but only 1.0
percent of runtime Python lines. Every shim is 18 lines, aliases exactly one
canonical module, and has no runtime importer. This is navigation debt, not
duplicated domain logic or a wrapper chain.

The ordinary implementation size distribution is:

| Lines | Modules |
|---|---:|
| 30 or fewer | 2 |
| 31 to 50 | 2 |
| 51 to 100 | 9 |
| 101 to 200 | 22 |
| 201 to 400 | 29 |
| More than 400 | 38 |

This distribution rejects a blanket minimum-file-size gate. It also shows why
the existing 1,000-line ceiling needs a cohesion counterweight. A size-only
split can turn one oversized module into several satellites that have no
independent owner, consumer, or test boundary.

The large-module debt is real even though micro-file sprawl is not. Production
source retains 32 too-many-argument findings, 19 too-many-return findings, 11
too-many-branch findings, and five too-many-statement findings under the
existing non-growth ratchet. Refactor priority must use the intersection of
function complexity, fan-in, fan-out, change pressure, and contract risk. A
large cohesive data or facade module is not equivalent to a large branching
orchestrator.

### Test shape

| Measure | Result |
|---|---:|
| Test Python files | 282 |
| Test Python lines | 70,713 |
| Named tests found statically | 4,214 |
| Median named tests per nonempty file | 10 |
| Files with one named test | 2 |
| Test files directly under `tests/` | 274 of 282 |
| Test files whose name mirrors one source basename | 48 of 276 |

Tiny test files are not the problem. The suite is broad and mostly flat. Five
historical catch-all files contain 204 tests and 3,538 lines:

- `tests/test_cli_coverage.py`
- `tests/test_cli_coverage_extra.py`
- `tests/test_formatter_coverage.py`
- `tests/test_gws_features.py`
- `tests/test_enhanced_yaml.py`

Large cohesive suites such as `tests/test_exposure.py` and
`tests/test_claim_contract.py` should remain intact. Test size alone is not a
reason to move or split them.

### Navigation and coupling

The source package is wide and shallow: 85 Python modules are at the package
root, 61 after compatibility shims are excluded, and 48 are under `cli/`,
`formatter/`, `mcp_client/`, `server/`, or `sources/`. The highest outgoing
dependency counts belong to expected orchestrators, including `cli/lookup.py`,
`cli/__init__.py`, `server/introspection.py`, `cli/batch.py`, and
`formatter/panel.py`.

The broad facades are more relevant than the tiny modules:

- `cli/__init__.py` is 930 lines and owns Typer registration.
- `formatter/__init__.py` exports 65 names and proxies mutable formatter state.
- `server/__init__.py` is 410 lines and owns public server startup behavior.
- `models.py` is 905 lines and has the widest source and test fan-in.

These are stable contract roots. Moving code solely to make their line counts
smaller can add another lookup hop without reducing complexity. Any change to
them requires a named responsibility, an impact review, and compatibility
evidence.

Formatter ownership currently has a concrete two-hop problem:
`formatter/__init__.py` imports 64 names through `formatter/panel.py`, while
`panel.py` re-exports 41 names from six defining formatter modules. Flattening
that internal ownership path is more valuable than introducing another
formatter submodule. The public identities and mutable-state proxy must remain
stable throughout v2.

Focused non-release history does not show a strong general pattern of tiny
modules always changing together. Only roughly 100 focused non-merge commits
are available, and several recent extractions have one commit of history. The
main repeated co-change cluster is the MCP server registration surface, which
is expected because registration order is one compatibility boundary.
Co-change is a review signal here, not a merge command.

## Boundary Rules

### Split a module only when

- the extracted capability has one nameable responsibility;
- it owns an independent invariant, safety boundary, test seam, consumer, or
  change cadence;
- dependencies still point in one understandable direction;
- callers do not need callbacks, shared mutable globals, or repeated
  cross-module traffic to use it;
- the change removes reader burden from the original module rather than moving
  it into another oversized file; and
- public imports and generated surfaces either remain stable or follow the
  documented compatibility process.

### Merge or delete a module only when

- it has one production consumer or none;
- it has no supported direct import contract;
- its invariants and change history are inseparable from the destination;
- removing it eliminates a navigation hop or shipped dead surface; and
- the destination remains cohesive and below its size ceiling.

### Keep a small module when

- it is a protocol, adapter, typed contract, resource boundary, security
  boundary, or independently tested algorithm;
- it prevents unsafe imports or dependency cycles; or
- combining it would make an already large module worse.

### Review policy

- A small change means one self-contained behavior change. It does not mean
  one new file per helper.
- New ordinary modules below 100 physical lines require a short boundary
  rationale in the change description. This is a review prompt, not a CI
  failure.
- No compatibility shim may point to another shim.
- Internal runtime code and ordinary tests use defining modules. Compatibility
  tests alone exercise legacy import paths.
- New top-level `recon_tool` modules require an owner category and a reason not
  to live in an existing local package.
- File size, direct fan-in, outgoing dependencies, direct owner tests, and
  change locality are reviewed together. No single metric decides structure.

## Ranked Plan

### 1. Make ownership navigable without moving code

Value: highest. Risk: low. Dependency: none.

- Add a tracked `tests/README.md` that maps behavior areas to defining source
  modules, focused test suites, and the canonical local commands.
- Link the map from `CONTRIBUTING.md`.
- Keep the generated local test map split into direct-import owners and
  heuristic candidates. Direct tests run first after a change.
- Label the 24 old top-level paths as compatibility-only in the ownership map.

Acceptance:

- A new contributor can find the defining module and focused tests for CLI,
  formatting, MCP, DNS sources, cache, inference, and validation without using
  repository-wide search.
- The map names no ignored file as canonical documentation.
- No runtime or public behavior changes.

### 2. Replace catch-all test ownership one suite at a time

Value: high. Risk: low to medium. Dependency: task 1.

- Move tests from the two CLI `coverage` suites to existing behavior-owned CLI,
  batch, doctor, explanation, exposure, and output-contract suites.
- Move `test_gws_features.py` cases to Google, DNS, merger, MTA-STS, and BIMI
  owners.
- Move `test_enhanced_yaml.py` cases to fingerprint, signal, and posture
  owners.
- Move formatter cases by output contract, not by which lines they happen to
  cover.

This is redistribution, not test consolidation. Preserve test intent and
collected count. Do not create a new file if an existing owner is clear, and do
not move cases into an already oversized or incoherent destination merely to
remove a catch-all filename.

Acceptance:

- The five catch-all filenames are gone.
- Collected tests do not decrease except for proven duplicate assertions.
- Coverage does not regress from the dated 90.52 percent branch-aware result
  and remains above the enforced 90.2 percent gate.
- Focused test commands become shorter and ownership is documented.

### 3. Resolve compatibility and runtime-package ownership debt

Value: high. Risk: medium. Dependency: published surface audit.

- Keep all 24 shims through the v2 compatibility line. Record their canonical
  target and earliest SemVer-safe removal release.
- Move ordinary tests and fuzz harnesses to canonical defining modules. Retain
  one explicit compatibility suite that proves every old path aliases exactly
  one canonical target.
- Audit private facade re-exports. Preserve documented public names and remove
  internal-only aliases only when source, tests, generated inventories, and
  downstream compatibility evidence agree.
- Make `formatter/__init__.py` import public names from their defining modules
  rather than routing them through `formatter/panel.py`, while preserving
  exported object identity and mutable-state proxy behavior. Treat private
  facade aliases as v3 removal candidates, not minor-release cleanup.
- Decide whether `sources/azure_metadata.py` is a supported direct source. It
  has no production importer and only test consumers. Document and integrate a
  named use case, or remove it.
- Decide whether `fingerprint_audit.py` and `validation_runner.py` belong in
  the installed runtime package. They total 781 lines and are active
  maintainer-only helpers imported by `validation/audit_fingerprints.py` and
  `validation/run_corpus.py`, plus tests. They are not dead code. Move them only
  if build, sdist, and maintainer command contracts remain explicit and
  testable.
- Keep the 10-line `surface_inventory.py` packaged-resource boundary. Folding
  it into another module would require a new compatibility hop without removing
  duplicated logic.

Acceptance:

- No runtime module is retained for a hypothetical future use.
- No v2 public import is broken.
- Runtime wheel contents and maintainer-only contents have documented owners.
- Shim count cannot grow, and the next breaking-release plan has an explicit
  removal gate.

### 4. Decompose only the measured interface hotspots

Value: medium to high. Risk: critical. Dependency: semantic and MCP stability
tracks in the roadmap.

- For `formatter/panel.py`, prefer one cohesive extraction of the auxiliary
  posture, chain, comparison, source-status, and explanation panels. Do not
  create one module per renderer or helper. Preserve the public facade and
  byte-equivalent golden output.
- For `server/introspection.py`, keep framework registration in one visible
  order. Consider extracting typed response contracts plus pure conversion
  helpers, not decorated tools one by one.
- Leave `cli/__init__.py` and `models.py` alone until a measured reader or
  change-isolation problem identifies a better boundary. Their broad fan-in is
  a reason for caution, not a reason for automatic decomposition.
- Rank any next target by combined PLR complexity, graph coupling, change
  pressure, and contract risk. Line count alone does not establish priority.

Acceptance:

- At least one special file-size allowance is removed or lowered by 20 percent.
- No new ordinary implementation module is below 100 lines without a named
  contract or safety seam.
- No public import, panel byte, MCP registration order, JSON schema, or
  generated inventory changes.
- No import cycle or wrapper-to-wrapper chain is introduced.
- Focused direct owner tests, graph-selected likely tests, and the full local
  gate pass.

### 5. Add a balanced structural ratchet

Value: preventative. Risk: low. Dependency: tasks 1 through 3 establish the
baseline.

- Extend the existing file-size and interface-layout checks instead of adding
  another standalone checker.
- Continue blocking oversized growth and new compatibility shims.
- Report, initially without blocking, new tiny one-consumer modules, new root
  modules, private facade re-exports, modules with no production importer, and
  wrapper depth.
- Promote only a stable, low-false-positive signal to a CI failure.

Acceptance:

- The report is deterministic, AST-based, and independent of ignored local
  graph files.
- Existing justified boundaries have explicit baselines.
- A synthetic bad fixture proves each promoted rule fails for the intended
  reason.
- The guard cannot be satisfied by trading a god file for arbitrary fragments.

## Explicit Non-Goals

- No bulk package reshuffle.
- No minimum line-count CI rule.
- No move of every prefix family into another subpackage.
- No deletion of v2 compatibility imports merely because in-repository callers
  have migrated.
- No test-directory migration in one large change.
- No refactor mixed with inference, collector, schema, or product behavior.

## Current External Guidance

Checked 2026-07-14 against primary sources and recent research:

- The [2025 DORA report](https://dora.dev/research/2025/dora-report/) describes
  AI as an amplifier of the engineering system around it. That supports
  strengthening ownership, review, and gates instead of treating generation
  speed as product progress.
- Google's [small change guidance](https://google.github.io/eng-practices/review/developer/small-cls.html)
  defines smallness as one self-contained change, notes that spreading a change
  across many files increases review size, and requires related tests. It does
  not recommend tiny permanent modules.
- Google's [code review guidance](https://google.github.io/eng-practices/review/reviewer/looking-for.html)
  treats complexity as code that readers cannot understand quickly, requires
  tests to remain maintainable, and asks reviewers to judge system-wide code
  health rather than isolated line counts.
- [ISO/IEC 25010:2023](https://www.iso.org/standard/78176.html), published
  November 2023, defines a product quality model intended to support measurable
  design objectives, test objectives, quality criteria, and acceptance
  criteria. The relevant application here is an evidence-backed maintainability
  plan, not a claim of certification.
- Cotroneo, Improta, and Liguori's
  [ISSRE 2025 study](https://arxiv.org/abs/2508.21634), submitted August 2025,
  compared more than 500,000 Python and Java samples. It found AI-generated code
  generally simpler and more repetitive, with more unused constructs and
  hardcoded debugging, and concluded that AI-assisted work needs specialized
  quality assurance.
- Cito and Bork's
  [November 2025 position paper](https://arxiv.org/abs/2511.02475) argues for
  recovering software models after generation to restore comprehension and
  guide refinement. recon's local code graph serves that orientation role, but
  its dynamic-registration uncertainty remains explicit.

These sources support one conclusion: keep changes small, keep boundaries
meaningful, and measure the repository as a system. They do not support a
universal preferred module size.
