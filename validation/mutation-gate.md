# Mutation testing promoted to a gate (2026-06)

The roadmap assurance track calls for "mutation testing promoted to a
gate with a score floor." The hand-rolled pilot
(`tests/test_mutation_resistance.py`, v1.9.9) and the deferral memo
(`validation/v1.9.10-mutation-status.md`) planned a cosmic-ray sweep as
CI work; this memo records the standing version of that gate.

Gate: `.github/workflows/mutation.yml`. Config: `mutation.toml` at the
repo root. Tool: cosmic-ray (the `mutation` dependency group), which
runs on both the Linux CI runner and the maintainer's Windows machine,
so the local gate can match CI.

## Scope: the inference core first

The mutated surface is `recon_tool/bayesian.py`: the Bayesian network
loader, the factor construction, variable elimination, the credible
interval, and the n_eff machinery. Chosen first because it is the
highest trust-per-effort surface: the numbers it emits are the product
recon asks operators to rely on, it is already the most-verified module
in the tree (differential verification in v2.1.7, the drift gate in
v2.1.14, interval coverage in v2.1.15), and mutation testing answers
the one question those harnesses do not: would the test suite notice if
this code were subtly wrong?

`formatter.py`, the other module the v1.9.10 memo named, is held by the
golden-render characterization suite (byte-identical output across the
decomposition); extending the mutation gate there is a future patch if
the cost stays proportionate.

## The kill-set

Each mutant runs a focused four-file kill-set rather than the full
suite, chosen for kill power per second (about 1.5 s per mutant versus
about 35 s for the full bayesian-adjacent suite):

- `tests/test_bayesian_inference.py`: the unit/behavior suite for the
  engine.
- `tests/test_bayesian_canonical.py`: hand-computed posterior anchors.
- `tests/test_bayesian_evidence_groups.py`: the CAL7 group-reduction
  and CAL14 declarative-absence branches.
- `tests/test_drift_check.py`: the committed CPT-implied-marginal
  fingerprint; deterministic and sensitive, it kills most arithmetic
  mutants in the inference path almost for free.

The full suite still runs every mutant's code path in the normal CI
`test` job; the kill-set is only the per-mutant economy. A baseline
step proves the kill-set passes unmutated before any mutant is scored,
so a broken kill-set cannot masquerade as a perfect score.

## Results (2026-06 baseline sweep)

Full sweep on the maintainer machine (Windows, Python 3.14, cosmic-ray
8.4.6):

- Mutants: 1,642 across `recon_tool/bayesian.py`.
- Killed: 1,642.
- Survived: 0.
- Kill score: 100%.
- Wall clock: about 60 minutes single-threaded.

Survivor dispositions (the policy: each survivor is either killed with
a new test or accepted here with a reason): none to disposition in the
baseline sweep. A perfect score is plausible here rather than
suspicious: the module is small and numerically anchored, and the
drift-gate test alone pins every node's CPT-implied prior, all-present
posterior, and interval width to four decimals against a committed
baseline, so nearly any arithmetic, comparison, or constant mutation in
the inference path moves a pinned number. Future sweeps may still
surface equivalent mutants (mutations with no observable effect); the
floor below leaves room to accept those explicitly rather than chase
them.

## The floor

`cr-rate --fail-over 5`: the job fails if survival exceeds 5% (kill
score below 95%). The measured baseline is well inside the floor, so
the gate has headroom for benign equivalent mutants (mutations that do
not change observable behavior, which mutation tools cannot fully
avoid) while still catching a real regression in test strength, which
moves the score by much more than headroom.

## When it runs

- On any push or PR that touches the mutated surface, the kill-set
  files, the config, or the workflow: there it is a blocking check.
- Weekly on a schedule, so toolchain drift or an interaction someone
  missed still surfaces.
- On demand via `workflow_dispatch`.

It deliberately does not run on every push: a full sweep costs about
half an hour of runner time, and a docs or catalog change cannot change
the mutation score of an untouched module. The per-push CI gates
(pytest + coverage, ruff, pyright, drift, interval coverage,
hostile-input fuzz) remain the fast feedback loop.

## Running it locally

```
uv sync --group mutation        # or: .venv/Scripts/pip install cosmic-ray
cosmic-ray baseline mutation.toml
cosmic-ray init mutation.toml mutation.sqlite
cosmic-ray exec mutation.toml mutation.sqlite
cr-report mutation.sqlite | tail -n 5
cr-rate mutation.sqlite --fail-over 5
```

The session file (`mutation.sqlite`) is regenerable and gitignored.
cosmic-ray mutates the working copy of `recon_tool/bayesian.py` in
place while executing and restores it afterward; do not edit the tree
or run other test commands concurrently, and check `git status` if a
run is interrupted.
