# Submission Freeze Checklist

Status: pre-submission gate. This checklist makes the paper and artifact freeze
repeatable. It is not a claim that an external submission, DOI archive, OpenSSF
Best Practices Badge project, or outside replication pass already exists.

Checked: 2026-06-30.

## External Boundaries

The freeze gate follows the project-facing parts of these current references:

- ACM artifact review and badging:
  <https://www.acm.org/publications/policies/artifact-review-and-badging-current>
- arXiv submission and ancillary-file guidance:
  <https://info.arxiv.org/help/submit/index.html> and
  <https://info.arxiv.org/help/ancillary_files.html>
- OpenSSF Scorecard checks and Best Practices criteria:
  <https://github.com/ossf/scorecard/blob/main/docs/checks.md> and
  <https://www.bestpractices.dev/en/criteria/0>
- SLSA, GitHub artifact attestations, and PyPI attestations:
  <https://slsa.dev/spec/v1.2/>,
  <https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations>,
  and <https://docs.pypi.org/attestations/>
- Zenodo GitHub release metadata guidance:
  <https://help.zenodo.org/docs/github/describe-software/citation-file/> and
  <https://help.zenodo.org/docs/github/describe-software/zenodo-json/>

## Freeze Scope

Freeze these surfaces together:

- `README.md`, `ROADMAP.md`, and [roadmap.md](roadmap.md);
- [external-writeup-plan.md](external-writeup-plan.md);
- [paper-draft.md](paper-draft.md), [paper-outline.md](paper-outline.md), and
  [paper-claim-map.md](paper-claim-map.md);
- [artifact-review.md](artifact-review.md), [archive-readiness.md](archive-readiness.md),
  [replication-runbook.md](replication-runbook.md), and
  [openssf-badge-readiness.md](openssf-badge-readiness.md);
- [paper-figures.md](paper-figures.md) and `docs/assets/paper/*.svg`;
- [../validation/2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md);
- `CITATION.cff`, release notes, and published release assets when package
  behavior, package metadata, or public artifacts change.

## Preconditions

Do not start the freeze unless these statements are true:

- `main` is clean and aligned with the protected GitHub branch.
- No runtime surface change is mixed into the paper package.
- No private corpus, real target list, per-domain result row, organization name,
  tenant ID, or unsuppressed small stratum is staged.
- The claim map names a support tier for each empirical sentence in the draft.
- Public-list numbers are robustness checks rather than population rates.
- M365 tenancy evidence remains corroboration rather than independent
  calibration.
- The 80 percent interval language remains model-internal and does not claim
  ground-truth frequentist coverage.
- The archive, badge, reviewed-PR, and outside-replication status lines describe
  only events that have actually happened.

## Local Freeze Commands

Run from the repository root:

| Gate | Command | Freeze interpretation |
|---|---|---|
| Claim audit | `uv run python scripts/check_paper_claims.py` | Draft, outline, claim map, current docs, and the latest public proof memo pointer agree. |
| Figure drift | `uv run python scripts/generate_paper_figures.py --check` | Committed figures are deterministic aggregate-safe outputs. |
| Public smoke proof | `uv run python -m validation.reproduce_paper_numbers --profile smoke --stamp submission-freeze-smoke-YYYYMMDD` | The public orchestrator runs without private corpora. |
| Full public proof | `uv run python -m validation.reproduce_paper_numbers --profile paper --stamp submission-freeze-paper-YYYYMMDD` | Public synthetic and model-internal proof rows reproduce. |
| Validation hygiene | `uv run python scripts/check_validation_hygiene.py` | Committed validation artifacts exclude private identifiers and raw rows. |
| Text hygiene | `uv run python scripts/check_text_hygiene.py` | Public prose follows repository text rules. |
| Local CI mirror | `uv run python scripts/check.py` | Lint, type checks, coverage, generated artifacts, hygiene checks, and ratchets pass. |
| Local release readiness | `uv run python scripts/release_readiness.py --allow-dirty` | Version, citation metadata, lockfile, roadmap, private-data hygiene, and release inputs agree locally. |

After pushing the exact freeze commit, run:

```bash
uv run python scripts/release_readiness.py --remote
```

Remote readiness checks the public branch, required GitHub Actions state,
Scorecard API freshness, PyPI release assets, GitHub Release assets, SBOM, and
provenance. It validates release state only. It does not validate empirical
paper claims.

## Claim Freeze Rules

No new empirical language may enter the draft without an explicit support tier
in [paper-claim-map.md](paper-claim-map.md). Use these stop rules:

- Do not state attacker prevalence, exploitability, or real-world
  false-positive rates.
- Do not state population rates or benchmark prevalence from public-list
  checks.
- Do not state ground-truth frequentist coverage for the 80 percent intervals.
- Do not state broad calibration or independent calibration.
- Do not describe private-corpus rows as externally reproduced.
- Do not promote a passive DNS or certificate-transparency observation into a
  confirmed active service, vulnerability, or security verdict.
- Do not add DOI, archive-badge, OpenSSF badge, reviewed-PR, contributor
  diversity, or outside-replication claims until the real external event exists.

If a claim cannot pass those rules, either remove it from the paper package or
mark the claim-map row as `Requires further evidence`.

## Freeze Record

The latest local public proof record for this checklist is
[../validation/2026-06-30-submission-freeze-local-proof.md](../validation/2026-06-30-submission-freeze-local-proof.md).
It is local proof evidence only; it is not an external submission, DOI archive,
OpenSSF badge, reviewed-PR, or outside-replication claim.

The freeze record should name:

- the exact commit SHA;
- the package version and release tag, if a package release is part of the
  freeze;
- the public smoke and full proof stamps;
- the latest public claim audit memo;
- the local gate and remote readiness result;
- any real external artifact identifiers, only after they exist.

Do not create `.zenodo.json`, DOI metadata, archive badges, or OpenSSF badge
links as placeholders. Do not publish a new PyPI or GitHub release for docs-only
or tests-only work unless package metadata or release artifacts changed.
