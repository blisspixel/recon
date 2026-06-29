# Public Replication Runbook

Status: instructions for an outside public-artifact replication pass. This file
does not claim that an outside replication pass has occurred, does not request
private data, and does not add runtime, dependency, schema, fingerprint, or
network behavior.

## Sources Checked

- ACM artifact review and badging:
  <https://www.acm.org/publications/policies/artifact-review-and-badging-current>
- Artifact review guide for this repository:
  [artifact-review.md](artifact-review.md)
- Current public proof memo:
  [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md)
- Archive readiness and DOI stop rules:
  [archive-readiness.md](archive-readiness.md)
- Security-aware artifact evaluation research:
  <https://arxiv.org/abs/2605.06508>

## Purpose

The replication pass asks an outside reviewer to rerun the public artifact on a
clean machine and report whether the public commands work as documented. It is
not a request to validate private-corpus rows or disclose real-domain data.

This strengthens the "functional" and public-result portions of the artifact
story while preserving the claim-map boundary:

- public synthetic and model-internal rows can be rerun;
- private-corpus rows remain aggregate evidence;
- the reviewer reports command outcomes and environment notes, not per-domain
  findings.

## Preconditions

Before sending this runbook to a reviewer:

1. `main` is clean and pushed.
2. GitHub CI, Secrets scan, and Scorecard pass on the target commit.
3. `uv run python scripts/check.py` passes locally.
4. `uv run python scripts/release_readiness.py --remote` passes on clean
   `main`.
5. The latest public proof memo pointer is current in
   `scripts/check_paper_claims.py`.
6. The reviewer receives only a commit, release tag, or repository URL, not a
   private corpus or target list.

## Reviewer Commands

Run these from a fresh clone of the target commit:

| Goal | Command | Outcome to record |
|---|---|---|
| Environment resolve | `uv sync` | Pass or fail, Python version, OS, and any resolver error. |
| Public proof smoke | `uv run python -m validation.reproduce_paper_numbers --profile smoke --stamp outside-replication-smoke` | Pass or fail; confirm the summary says no private corpora and no default network requirement. |
| Full public proof | `uv run python -m validation.reproduce_paper_numbers --profile paper --stamp outside-replication-paper` | Pass or fail; record the five public step statuses only. |
| Paper figure drift | `uv run python scripts/generate_paper_figures.py --check` | Pass or fail. |
| Local CI mirror | `uv run python scripts/check.py` | Pass or fail, final test count, skipped count, and coverage percentage. |
| Local release readiness | `uv run python scripts/release_readiness.py` | Pass or fail. |

The reviewer may also run `uv run python scripts/release_readiness.py --remote`
after the release is public. That checks publication state and provenance, not
empirical paper results.

## Safe Outcome Note

Record only aggregate outcome notes in a future public memo or appendix:

- reviewer role, not personal contact details unless they request attribution;
- operating system and Python version;
- commit or release tag reviewed;
- command pass/fail statuses;
- final local gate test count, skipped count, and coverage percentage;
- public proof step statuses;
- any non-secret installation or environment issue.

Do not record:

- real apex domains;
- organization names as targets;
- tenant IDs;
- per-domain outputs;
- raw private corpus rows;
- unsuppressed small strata;
- reviewer credentials, tokens, or local paths containing personal information.

## Interpretation

Use conservative language:

- "An outside reviewer reproduced the public proof commands" is acceptable only
  after that pass happens.
- "Private-corpus rows were independently reproduced" is not acceptable unless
  a separate data-handling and architecture review approves a disclosure-safe
  path.
- "Published release provenance verified" is release-state evidence, not
  empirical result validation.
- "Results validated" applies only to rows the reviewer actually reran from the
  public artifact.

## Stop Rules

- Do not send private corpora, target lists, tenant IDs, or per-domain JSON to a
  reviewer through this runbook.
- Do not ask a reviewer to query real organizations beyond the committed public
  proof commands.
- Do not publish a replication memo that contains personal contact data,
  machine-local secret paths, credentials, or private target identifiers.
- Do not change the runtime surface to make replication easier unless the
  roadmap separately approves that surface change.
