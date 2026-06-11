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
identical local sweep in a CI-equivalent clone.

- Mutants generated: 1,642; annotation-equivalents filtered: PENDING.
- Tested: PENDING. Killed: PENDING. Survived: PENDING.
- Survival rate over tested mutants: PENDING.
- Accepted equivalents (each with reason): PENDING.

## The floor

`scripts/mutation_floor.py mutation.sqlite --fail-over 5`: survival
over **tested** mutants (killed + survived) must stay at or under 5%.
The script replaces `cr-rate`, whose accounting divides kills by every
recorded result and therefore counts filter-skipped jobs as if they had
survived; the script also fails outright on incompetent results (a
broken worker means the score measures nothing) and on pending jobs (a
partial sweep is not a score).

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
