# Maintainer validation loop (PV2)

A maintainer-side routine, run by an agent rather than by hand, that keeps the
Bayesian CPT numbers and the fingerprint catalog honest as the world drifts. It
is maintainer-facing and never something an end user runs.

Use this with the generic loop guardrails in
[maintainer-loop-runbook.md](maintainer-loop-runbook.md): ignored local state,
deterministic gates, explicit stop conditions, spend tracking, and maintainer
review for semantic changes.

The premise sets the discipline: the priors and likelihoods are
directionally-accurate, corpus-grounded estimates, not values precise to many
decimals, and they are not meant to be. The credible interval already carries
the residual uncertainty (see [correlation.md](correlation.md)). So the right
posture is "grounded this release, re-checked next," not false precision. The
loop's job is to notice when a number has moved enough to matter and surface it
for review.

The steps are tiered by data sensitivity, from "runs anywhere, committed and
CI-gated" to "stays on the maintainer's machine against the gitignored corpus."
Only deterministic or aggregate output is ever committed; the corpus and any
per-domain results stay in the gitignored paths
([corpus-private structure](../validation/README.md)).

## Tier 0: the inference drift gate (committed, CI-gated)

The Bayesian network's CPT-implied marginals are deterministic from
`bayesian_network.yaml` with no corpus, so they can be fingerprinted, committed,
and gated on every change.

- `validation/drift_check.py` fingerprints every node's no-evidence **prior
  marginal**, its **all-bindings-present posterior**, and that posterior's
  **interval width**. Two fixed evidence configurations make the fingerprint
  sensitive to both a changed prior and a changed likelihood / CPT entry.
- `validation/inference_baseline.json` is the committed baseline (node names and
  numbers only, no company data).
- `tests/test_drift_check.py::test_shipped_network_matches_committed_baseline`
  is the gate: an edit to the network that shifts an implied distribution beyond
  `_MARGINAL_BAND` (0.01 absolute) fails the test until the baseline is
  regenerated and committed.

This mechanically enforces the [CPT-change discipline](bayesian-cpt-discipline.md):
you cannot silently move the inference layer's implied distributions. When a
change is intended, the maintainer (or the agent) runs:

```bash
python -m validation.drift_check            # check (nonzero exit on un-acknowledged drift)
python -m validation.drift_check --json      # the same, agent-readable
python -m validation.drift_check --update     # regenerate the baseline after an intended change
```

and commits the new baseline next to the network edit, so the implied-distribution
shift is reviewed in the same diff.

## Tier 1: synthetic harnesses (no data, runs anywhere)

These need no corpus and run in CI or on any machine:

- `validation/differential_verification.py` cross-checks variable elimination
  against an independent full-joint reference (the "Trusted" item; anchored by
  `tests/test_bayesian_differential.py`).
- `validation/synthetic_calibration.py` and `validation/likelihood_sensitivity.py`
  (CAL8) perturb the likelihoods by +/-20% and confirm the posteriors and the
  deterministic-vs-Bayesian agreement stay stable.
- `validation/threshold_sensitivity.py` sweeps the trigger thresholds.

## Tier 2: external case-study spot-check (public web + recon)

A small, anonymized corroboration against independently-known public facts (the
provider's own DMARC/SPF records, the M365/GWS identity endpoints). It needs only
public web access plus recon, never the private corpus, and is reported as an
external sanity check, not calibration (see
[C3 framing in the roadmap](roadmap.md)). The committed artifact is aggregate:
counts of corroborated vs contradicted detections, no apexes.

## Tier 3: corpus re-grounding + firing-rate drift (maintainer-local)

This is the only tier that touches the gitignored corpus, and it stays on the
maintainer's machine:

1. A fresh corpus scan with `validation/scan.py` (resolve the corpus, with the CT
   rate-limit / multi-session workflow).
2. Re-ground the node base rates from the scan and compare them to the priors in
   `bayesian_network.yaml` (CAL12: priors documented against observed base rates).
3. `validation/compute_node_stability.py` for the per-node firing counts,
   coverage, and proxy-label calibration diagnostics.
4. A firing-rate **drift comparison** against the previous release: catalog
   firing rates and CPT-implied distributions are expected to move only within a
   band release-to-release; a larger move is flagged.

Only the aggregate metrics (counts, calibration numbers, drift deltas) reach the
repo; the apexes and per-domain output never do.

## What the agent does with the result

The agent runs Tier 0 (`drift_check --json`), the Tier 1 harnesses, and, on the
maintainer's machine, Tier 3, then reads the deltas. If a number moved materially
it opens an issue or proposes a CPT-update PR with the reasoning, under the
CPT-change discipline, with the maintainer approving any semantic change. Tier 0
is also a hard gate in CI, so an un-acknowledged inference shift cannot reach a
release regardless of whether the loop ran.

This is a natural fit for the existing agent surface (the harnesses, the
`agents/` scaffolding, and a `/schedule`-style routine). It is not a v2.0 gate
and not a hosted service; it is a maintainer routine.

As of 2026-06-11 the corpus-free portion is wired: a weekly scheduled agent
routine (`pv2-maintainer-validation`, Mondays) runs Tier 0, the Tier 1
harnesses, and the interval-coverage check against the documented bands, and
opens an aggregate-numbers-only issue when something moves materially. The
routine is barred from changing CPT semantics (the CPT-change discipline holds)
and from including any real company name or apex in anything it writes. Tier 3
remains maintainer-local by design.
