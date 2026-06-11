# Mutation testing promoted to a gate (2026-06)

The roadmap assurance track calls for "mutation testing promoted to a
gate with a score floor." The hand-rolled pilot
(`tests/test_mutation_resistance.py`, v1.9.9) and the deferral memo
(`validation/v1.9.10-mutation-status.md`) planned a cosmic-ray sweep as
CI work; this memo records the standing gate, including the false
start, because the correction is the most instructive part.

Gate: `.github/workflows/mutation.yml`. Config: `mutation.toml`. Floor:
`scripts/mutation_floor.py`. Tool: cosmic-ray (the `mutation`
dependency group).

## The v2.1.16 baseline was an artifact, and what caught it

The first sweep (run on the maintainer's Windows machine) reported
1,642 of 1,642 mutants killed. That number was wrong, and the v2.1.16
release notes repeated it. What actually happened: cosmic-ray's worker
spawns the test command with no shell, and the command began with a
bare `python`. On Windows, a bare program name resolves through the
CreateProcess search order, whose first stop is the directory of the
*base interpreter image*, not the virtual environment, so every mutant
was "tested" by an interpreter whose environment cannot even import the
test suite's conftest (`No module named hypothesis`). Every mutant
"died" of an instant collection error, never of a test verdict: a false
100% kill score.

It was caught by the gate's own design. The CI workflow includes a
baseline step (the kill-set must pass on unmutated code before any
mutant is scored) that the by-hand local run had skipped; on the Linux
runner, where `PATH` resolution under `uv run` is correct, the same
sweep produced 486 survivors out of 1,642, and the disagreement forced
the diagnosis. A second local sweep in a CI-equivalent clone (locked
venv, baseline verified first) reproduced the CI number, 486 of 1,642,
identically. The falsifiability lesson generalizes: an autonomous loop
is only as good as the checks inside it, and "the test command itself
is broken" is the failure mode the baseline step exists to catch.

Two mechanical fixes prevent recurrence:

- The test command starts with the `pytest` console script, never bare
  `python`. The console script lives in the venv's scripts directory,
  which is the first place both platforms' resolution looks for the
  spawning process's siblings, so the workers test the interpreter that
  has the project and its test dependencies.
- `cosmic-ray baseline` is mandatory before any scored sweep, in CI and
  in the local recipe below.

## Scope: the inference core first

The mutated surface is `recon_tool/bayesian.py`: the network loader,
factor construction, variable elimination, the credible interval, and
the n_eff machinery. Chosen first because it is the highest
trust-per-effort surface: the numbers it emits are the product recon
asks operators to rely on, it is already the most-verified module in
the tree (differential verification v2.1.7, drift gate v2.1.14,
interval coverage v2.1.15), and mutation testing answers the question
those harnesses do not: would the suite notice if this code were subtly
wrong?

## What the real survivors taught, and the response

The 486 genuine survivors clustered in code the original four-file
kill-set exercises only indirectly, which is to say: the mutation gate
found real test gaps on its first honest run.

| Cluster | Survivors | Response |
|---|---|---|
| `_credible_interval` / `_erfinv` (the interval arithmetic) | 83 | `tests/test_bayesian_unit_math.py`: hand-computed interval values per branch, erfinv anchors and symmetry |
| `_declarative_evidence_count` (CAL14 n_eff) | 53 | hand-computed counting cases (fired, informative absence, uninformative absence, group handling) |
| `_rank_evidence` / `_contributing_evidence` | ~45 | hand-computed LLRs, influence shares, tie-breaks, group reduction |
| parsers / loaders (`_parse_*`, `load_network`, `load_priors_override`) | ~95 | `tests/test_bayesian_validation_rounds.py` + `tests/test_bayesian_topology.py` added to the kill-set; loader edge cases in the unit file |
| TenantInfo adapters (`infer_from_tenant_info`, `signals_from_tenant_info`, `_conflict_provenance`) | ~35 | adapter unit tests (signal derivation, conflict provenance, interval dampening) |
| deal-contract predicates | ~30 | direct predicate tests (a weakened contract is invisible on correct code) |
| annotation-union operators (`X \| None` under `from __future__ import annotations`) | ~170 | equivalent by construction (the annotation never executes); excluded via the operators filter in `mutation.toml`, applied by `cr-filter-operators` |
| output rounding (`round(x, 4)`) | few | granularity assertions in the unit file (4-decimal exactly: a 3- or 5-decimal emission fails) |

The remaining long tail is re-measured by the corrected sweep; any
survivor that stays is either killed with a test or accepted in the
table below with a reason.

## Results (corrected baseline, 2026-06)

Authoritative run: the CI `mutation-gate` workflow on ubuntu (locked
venv, baseline-verified, operators filter applied), cross-checked by an
identical local sweep in a CI-equivalent clone. The honest corrected
trajectory, against the false v2.1.16 "1,642 of 1,642":

| Round | Tested | Killed | Survived | Survival | What changed |
|---|---|---|---|---|---|
| 1 (corrected) | 1,465 | 1,252 | 213 | 14.5% | interpreter fixed, BitOr filter, unit-math anchors |
| 2 | 1,465 | 1,312 | 153 | 10.4% | loader-edge + n_eff tests added |
| 3 (final) | 1,431 | 1,308 | 123 | 8.6% | Is/IsNot filtered, bound + penalty + absence kills |

(Final run: 1,642 mutants generated, 210 filtered as equivalent-by-construction,
1 incompetent within tolerance, so 1,431 tested.)

The first two rounds killed 60+ genuine survivors that were real test
gaps the gate exposed (loaders, n_eff arithmetic, interval math,
TenantInfo adapters, contract predicates). The third round filters the
identity-comparison mutants (equivalent by construction) and kills the
last cheap genuine survivors (out-of-range bound checks, the conflict
penalty constant asserted as a literal, the `absence_informative` flip).

**The residual 8.6% is dominated by equivalent mutants**, classified from
the survivor diffs (the session DB is uploaded as a CI artifact on every
run, so this is checkable):

- *Identity for value equality* (`==` to `is`): filtered. Testing object
  identity for an interned-literal comparison asserts a CPython
  implementation detail, not behaviour.
- *Ordering for equality* (`==` to `<=` / `>=` / `<` / `>` on a string or
  enum): equivalent, because every `==` in this module compares a string,
  an enum, or `None`, never a number whose order carries meaning, and the
  operand domains (`"DKIM"`, `"slug"`, `"declarative"`, ...) have no
  lexicographic neighbour the test data could exercise. Accepted, not
  filtered, so a future numeric `==` is not silently masked.
- *Arithmetic by 1.0* (`*` to `/` / `**` / `//` on `_EVIDENCE_N_EFF_CONTRIB`,
  which is `1.0`): `x * 1.0 == x / 1.0 == x ** 1.0`, so the operator is
  irrelevant. Mathematically equivalent.
- *Frozen-dataclass flags* (`frozen=True` to `False`): no code path mutates
  these instances, so the flag is behaviourally invisible; killing it would
  mean asserting that assignment raises, a language-feature test.
- *Always-true contract decorators* (`@deal.post(...)` removed): the
  postconditions hold on every valid input and are disabled under `-O`, so
  removing an assertion that never fires changes nothing observable.
- *Order-invariant loop and traversal mutants* (`queue.pop(0)` to
  `pop(-1)`, some `continue` to `break`): the topological sort accepts any
  valid order and checks only the visited count, so the traversal order
  does not change the result.

## The floor

`scripts/mutation_floor.py mutation.sqlite --fail-over 12`: survival over
**tested** mutants (killed + survived) must stay at or under 12% (kill
score at or above 88%). The floor sits above the documented
equivalent-mutant residue (measured 8.6%) with margin, so it ratchets the current
kill strength and fails when real coverage regresses (untested new code
spikes survival well past the residue), without demanding tests for
provably-equivalent mutants. This is the standard mutation-testing
posture: kill the genuine survivors, classify and accept the equivalents,
set a defensible floor, never chase 100%. The 5% figure the v2.1.16 notes
implied was never real; it was the wrong-interpreter artifact described
above.

The script replaces `cr-rate`, whose accounting divides kills by every
recorded result and therefore counts filter-skipped jobs as if they had
survived; the script also fails outright on incompetent results (a broken
worker means the score measures nothing) and on pending jobs (a partial
sweep is not a score).

## When it runs

- Blocking on any push or PR that touches the mutated surface, the
  kill-set files, the config, the floor script, or the workflow.
- Weekly on a schedule, so toolchain drift still surfaces.
- On demand via `workflow_dispatch`.

Not per-push: a full sweep costs about an hour of runner time, and a
docs or catalog change cannot change the mutation score of an untouched
module.

## Running it locally (Windows notes earned the hard way)

```powershell
# A non-OneDrive clone with the locked venv; uv sync works there.
git clone . $env:TEMP\recon-mutation; cd $env:TEMP\recon-mutation
$env:UV_PYTHON = "3.11"; $env:UV_LINK_MODE = "copy"
$env:PYTHONIOENCODING = "utf-8"   # cosmic-ray decodes worker output as UTF-8;
                                   # Windows pytest otherwise emits cp1252 and
                                   # a killed mutant is misrecorded as incompetent
uv sync --group mutation
uv run --group mutation cosmic-ray baseline mutation.toml   # mandatory
uv run --group mutation cosmic-ray init mutation.toml mutation.sqlite
uv run --group mutation cr-filter-operators mutation.sqlite mutation.toml
uv run --group mutation cosmic-ray exec mutation.toml mutation.sqlite
uv run python scripts/mutation_floor.py mutation.sqlite --fail-over 5
```

cosmic-ray mutates the working copy of `recon_tool/bayesian.py` in
place during exec and restores it afterward; do not edit the tree, run
other test commands, or run `uv` commands in that clone while it
executes (a concurrent `uv run` resync produced the one batch of
genuinely incompetent results we observed). Check `git status` if a run
is interrupted.
