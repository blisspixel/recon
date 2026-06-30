# OpenSSF Badge Readiness

Status: questionnaire-preparation worksheet. This file does not claim an
OpenSSF Best Practices Badge, does not add a badge URL, and does not change
repository rules.

## Sources Checked

- OpenSSF Best Practices Badge passing criteria:
  <https://www.bestpractices.dev/en/criteria/0>
- OpenSSF Scorecard check definitions:
  <https://github.com/ossf/scorecard/blob/main/docs/checks.md>
- Current recon OpenSSF posture:
  [openssf-posture.md](openssf-posture.md)
- Supply-chain and release integrity:
  [supply-chain.md](supply-chain.md)

## Policy

Complete the real `bestpractices.dev` questionnaire before adding any badge
link. A badge link must point to the actual project page and must reflect
honest answers that match the repository at the time it is added.

Do not add:

- a placeholder badge;
- a guessed project URL;
- a claim that the questionnaire is complete;
- artificial contributor diversity;
- manufactured pull-request review history.

## Passing-Level Evidence Map

This map prepares evidence for the passing-level questionnaire. It is not the
questionnaire itself.

| Criteria area | Local evidence | Current answer posture |
|---|---|---|
| Basics | README, Apache-2.0 license, public repository, PyPI package metadata, release tags, changelog, and documented install path. | Ready to answer from committed docs and package metadata. |
| Change control | SemVer policy, `CHANGELOG.md`, release process, protected `main`, required checks, CODEOWNERS, and tagged releases. | Ready for single-maintainer workflow wording; do not imply mandatory reviewed PRs. |
| Reporting | `SECURITY.md`, vulnerability contact path, issue templates, contribution policy, no-real-company-data policy, and neutral scope boundaries. | Ready to answer with repository links. |
| Quality | `scripts/check.py`, branch coverage floor, pyright, ruff, property tests, fuzzing, generated-artifact drift checks, mutation gate, and release readiness. | Ready to answer with local and CI evidence. |
| Security | CodeQL, secret scanning, workflow pinning, least-privilege tokens, dependency updates, `pip-audit`, SBOM, Trusted Publishing, PyPI attestations, GitHub build provenance, and remote release readiness. | Ready to answer from supply-chain docs and workflow files. |
| Analysis | Static typing, static lint, release-readiness checks, validation hygiene, text hygiene, schema drift checks, and artifact guards. | Ready to answer with commands and CI jobs. |

## Questionnaire Answer Discipline

The badge criteria are evidence-driven. Many criteria ask for a public
URL or explicit justification. Use this discipline before submitting answers:

- Answer `Met` only when the answer can cite committed project evidence or a
  live public repository setting.
- Answer `N/A` only when the criterion itself permits N/A and the justification
  is accurate for recon's passive local-tool scope.
- Treat OpenSSF Scorecard as an automated signal, not as a substitute for a
  Best Practices questionnaire answer.
- Do not answer from maintainer memory, private repository settings, local run
  artifacts, or planned future work.
- For every non-trivial answer, record the evidence URL, the exact claim it
  supports, and any boundary that prevents stronger wording.
- If an answer would require a mandatory reviewed-PR process, contributor
  diversity, a third-party audit, a badge URL, or a long-term-support promise
  that does not exist, leave the answer weaker and document the gap.

## Answers That Need Care

Some answers must stay precise:

- Reviewed changes: CODEOWNERS and required checks exist, but normal maintainer
  work still lands through direct `main` commits. Do not claim a mandatory
  reviewed-PR process until the workflow actually changes.
- Contributors: the project is single-maintainer today. Do not imply
  organization diversity that does not exist.
- Badge status: the badge is absent until a real `bestpractices.dev` project
  exists.
- Third-party audits: no recurring third-party audit is claimed. The project
  relies on open source review, CI, security scanning, and reproducible
  provenance.
- Long-term support: no LTS branch is promised. The supported path is the
  current release line and SemVer compatibility.

## Before Adding A Badge Link

1. Create or update the real project on `bestpractices.dev`.
2. Answer every passing-level question from committed evidence.
3. Recheck that no answer depends on future intent, private data, or fake
   review history.
4. Add the real project link only after the project page exists.
5. Run `uv run pytest tests/test_scorecard_posture.py`.
6. Run `uv run python scripts/check.py`.
7. Push and verify GitHub CI, Secrets scan, Scorecard, and
   `uv run python scripts/release_readiness.py --remote`.

## Stop Rules

- No badge link until the real badge project exists.
- No placeholder URL.
- No claim that a badge is "in progress" as a substitute for the public page.
- No answer that depends on private corpora, target lists, tenant IDs,
  per-domain findings, or unsuppressed small strata.
- No artificial contributors or manufactured review history.
