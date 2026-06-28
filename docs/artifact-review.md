# Artifact Review Guide

Status: reviewer-facing guide for external write-up readiness. This file defines
what an outside reviewer can run, what result each command validates, and which
paper claims remain maintainer-reproducible only.

## Scope

The review artifact is the repository at a specific commit plus the released
Python package built from that source. It includes:

- the CLI, importable package, and local stdio MCP server;
- the stable JSON schema in [recon-schema.json](recon-schema.json);
- public proof and synthetic validation harnesses under `validation/`;
- aggregate-only validation memos under `validation/*.md`;
- the aggregate-safe paper figure package in [paper-figures.md](paper-figures.md)
  and `assets/paper/*.svg`;
- the public label snapshot and public-list sampling decision in
  [public-label-snapshot-decision.md](public-label-snapshot-decision.md);
- citation metadata in [../CITATION.cff](../CITATION.cff);
- supply-chain and release-integrity notes in [supply-chain.md](supply-chain.md).

The artifact does not include private corpora, per-domain outputs, real target
lists, paid feeds, credentials, or hosted services.

## Reviewer Commands

Run from the repository root after installing the development environment:

| Goal | Command | Expected result |
|---|---|---|
| Install dependencies | `uv sync` | Development environment resolves from `uv.lock`. |
| Quick public proof smoke | `uv run python -m validation.reproduce_paper_numbers --profile smoke --stamp artifact-review-smoke` | Writes a manifest and summary under `validation/local/paper-numbers/artifact-review-smoke/`; reports no private corpora and no default network requirement. |
| Full public proof bundle | `uv run python -m validation.reproduce_paper_numbers --profile paper --stamp artifact-review-paper` | Runs suppression monotonicity, differential verification, interval coverage, likelihood sensitivity, and layer ablation. |
| Paper figure drift check | `uv run python scripts/generate_paper_figures.py --check` | Verifies the committed SVG figures match the deterministic aggregate-safe generator. |
| Local CI mirror | `uv run python scripts/check.py` | Ruff, pyright, coverage-gated tests, generated-artifact checks, hygiene checks, and ratchets pass. |
| Release readiness | `uv run python scripts/release_readiness.py` | Version, citation metadata, lockfile, roadmap, Homebrew formula, private-data hygiene, and commit hygiene pass for the local checkout. |

If a Windows terminal closes stdout during the long coverage run, redirect the
wrapper output to `logs/check-full.log`. `logs/` is ignored:

```powershell
uv run python scripts/check.py > logs\check-full.log 2>&1
```

That changes only terminal handling. It does not skip any gate.

## What The Public Bundle Validates

The latest maintainer full proof check is recorded in
[../validation/2026-06-28-final-claim-audit.md](../validation/2026-06-28-final-claim-audit.md).
That memo is the current final public claim audit for the draft package. It
supersedes the earlier adversarial-perturbation proof memo only as the latest
submission gate; the earlier memo remains the focused record for the
add/remove perturbation harness.

| Claim family | Public command or gate | Reviewer interpretation |
|---|---|---|
| Inference arithmetic | `validation.differential_verification` through the reproduction bundle | Variable elimination matches an independent full-joint reference over enumerable shipped configurations. |
| Evidence-removal and planting boundary | `validation.adversarial_properties` through the reproduction bundle | Suppression monotonicity holds for evidence removal, and synthetic add/remove perturbation summaries show that planted evidence can raise posteriors across decision boundaries. |
| Interval perturbation coverage | `validation.interval_coverage --json` through the reproduction bundle | The 80 percent interval absorbs the CAL8 likelihood band inside the model. This is not ground-truth coverage. |
| Likelihood sensitivity | `validation.likelihood_sensitivity` through the reproduction bundle | Posterior decisions are stable under the configured +/-20 percent likelihood perturbation. |
| Layer contribution | `validation.layer_ablation` through the reproduction bundle | Synthetic graph and Bayesian layer effects reproduce without target data. |
| Public-list sampling boundary | [public-label-snapshot-decision.md](public-label-snapshot-decision.md) plus `scripts/check_paper_claims.py` | Public-list numbers are robustness checks rather than population rates or benchmark prevalence. |
| Paper figures | `scripts/generate_paper_figures.py --check` | SVG figures are deterministic renderings of committed topology and aggregate memos, not hand-edited screenshots. |
| Runtime and docs integrity | `scripts/check.py` | Generated schema, surface inventory, CLI surface docs, text hygiene, validation hygiene, and tests agree with source. |

## What Is Not Publicly Reproducible

Some paper rows use real-domain corpora that cannot be committed under the
data-handling policy:

- DMARC full-posterior consistency and held-out residual aggregates in
  [../validation/2026-06-28-full-corpus-calibration-refresh.md](../validation/2026-06-28-full-corpus-calibration-refresh.md).
- M365 DNS-only provider corroboration aggregates in the same memo. The
  [M365 tenancy decision](m365-tenancy-decision.md) explains why this remains
  corroboration rather than independent calibration.
- Aggregate-only certificate-transparency validation closure in
  [../validation/2026-06-26-c3-ct-partial.md](../validation/2026-06-26-c3-ct-partial.md).

These are maintainer-reproducible aggregate results. Reviewers can inspect the
memo, disclosure controls, and harness code, but they cannot regenerate the
private rows from the public repository. The [paper claim map](paper-claim-map.md)
records this distinction claim by claim.

Public-list cross-checks are public and re-queryable, but the project does not
publish a frozen real-apex label snapshot for this submission. Treat those
numbers as robustness checks rather than population rates.

## Disclosure Controls

Reviewers should expect committed artifacts to contain:

- counts, rates, intervals, quantiles, and aggregate deltas;
- fictional examples and reserved domains;
- vendor names when they are detection classes.

Reviewers should not find:

- real apex lists;
- organization names as targets;
- tenant IDs;
- per-domain findings;
- raw private corpus rows;
- unsuppressed small strata.

The mechanical backstops are `scripts/check_validation_hygiene.py`,
`tests/test_validation_hygiene.py`, and release readiness. Semantic review still
owns prose that a regex cannot classify.

## Review Outcome Language

Use these labels when writing the artifact appendix:

- Available: repository, release assets, license, docs, and citation metadata are
  present.
- Functional: the public proof bundle and local CI mirror run successfully.
- Reusable: the README, docs index, schema, operational contract, and data policy
  are sufficient to rerun the public artifact and understand limits.
- Results validated: only the public proof and synthetic rows qualify for an
  outside reviewer. Private-corpus rows are aggregate evidence, not externally
  reproduced results.
