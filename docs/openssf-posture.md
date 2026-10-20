# OpenSSF Posture

This note records the current OpenSSF path for recon. It is intentionally
separate from the public Scorecard badge: Scorecard is an automated signal,
while the Best Practices Badge is an account-backed project questionnaire.

## Current Snapshot

- Date checked: 2026-10-20.
- Live API state at check time: public API rechecked for the exact current
  release `HEAD` after CI and publication completed.
- Scorecard version: `v5.6.0`.
- Score: `8.4`.
- Public source: `https://api.securityscorecards.dev/projects/github.com/blisspixel/recon`.

The public API is authoritative for the exact commit behind the badge. Docs-only
commits can move `main` after a snapshot is written, so this file records the
reviewed posture and the live API URL rather than treating a commit hash as a
durable status promise. Remote release readiness queries that API for `HEAD`,
requires an overall score of at least `8.0`, keeps the non-SAST required
code-owned controls at `10`, and requires the documented SAST floor of `10`.

The measured code-owned controls are green: dangerous workflow patterns,
dependency update automation, token permissions, pinned dependencies, binary
artifacts, security policy, known vulnerabilities, packaging, fuzzing, signed
releases, license and SAST all score `10`. CI-Tests also scores `10` because
every sampled merged pull request ran CI. The public API reports successful
supported SAST checks for every merged pull request in its sampled window.
Current pull requests provide supported SAST evidence; pull requests targeting
`main` and pushes to `main` run CodeQL, while weekly and manual main analysis
remain available. The temporary SAST floor of `7` is retired. The sample size
and overall score remain dated external state, not a permanent promise.

The remaining low or unknown checks are process-bound:

| Check | Current reason | Real next step |
|---|---|---|
| `Branch-Protection` | `main` requires PRs, strict CI, CodeQL and gitleaks, linear history, no deletion or force pushes, and no bypass actors. Independent approvals, last-push approval and required CODEOWNERS review are absent because there is one maintainer. | Stale approvals are dismissed and review threads must resolve. Release readiness enforces these controls. Add independent approval requirements when a second qualified reviewer is available. |
| `Code-Review` | No human-approved changesets appear in Scorecard's sampled window; automated review comments are not approvals. | Use normal reviewed PRs for non-urgent work when there is another qualified reviewer. Do not manufacture review history. |
| `CII-Best-Practices` | No OpenSSF Best Practices Badge project is linked. | Use [openssf-badge-readiness.md](openssf-badge-readiness.md) to answer the questionnaire from committed evidence; link a badge only after the real project page exists and the answers match the repository. |
| `Contributors` | Scorecard sees no contributor diversity across organizations. | Accept this for a single-maintainer project. Do not add artificial contributors. |

## Best Practices Badge Readiness

The detailed worksheet lives in
[openssf-badge-readiness.md](openssf-badge-readiness.md). The OpenSSF Best
Practices Badge criteria are organized around basics, change control,
reporting, quality, security, and analysis. recon already has local evidence
for many passing-level questions. The root
[.project.d/bestpractices.json](../.project.d/bestpractices.json) supplies all 67 criterion proposals
to the badge service, with unknown answers for personal attestations and
unverified response history. It does not create a badge project or claim a
passing result:

| Area | Local evidence |
|---|---|
| Basics | README, Apache-2.0 license, PyPI package metadata, documented install and update path, public issue tracker, and stable project URLs. |
| Change control | Git history, SemVer policy, changelog, release process, tagged releases, signed provenance assets, and short-lived branch guidance. |
| Reporting | `SECURITY.md`, private vulnerability-reporting email, response timeline, issue templates, and no-real-company-data contribution policy. |
| Quality | `scripts/check.py` as the canonical local gate, branch coverage gate, mutation gate, property tests, fuzzing, golden renders, pyright strict mode, and generated-artifact drift guards. |
| Security | CodeQL, ruff security rules, `pip-audit`, secret scanning, push protection, least-privilege workflow tokens, pinned workflow actions, SBOM, same-job deterministic-build checks, Trusted Publishing, PyPI attestations, and GitHub build provenance. |
| Analysis | Strict type checking, static analysis, workflow-pin checks, validation hygiene, text hygiene, schema drift checks, and release readiness checks. |

No OpenSSF Best Practices Badge is claimed in this repository until the project
exists on `bestpractices.dev` and the questionnaire is answered honestly from
the worksheet. A future badge link must point to the real project page and must
not be added as a placeholder.

## CODEOWNERS Decision

`.github/CODEOWNERS` routes all repository paths to `@blisspixel` so external
pull requests have clear ownership. This does not by itself create a
Scorecard-reviewed workflow. It is preparation for a future branch ruleset that
requires CODEOWNERS review when a second qualified maintainer is available.
Maintainer changes already use checked pull requests; the author cannot supply
an independent approval of their own change. Outside contributors and
prospective reviewers are welcome through [CONTRIBUTING.md](../CONTRIBUTING.md).

## Research Sources

- OpenSSF Scorecard check definitions:
  `https://github.com/ossf/scorecard/blob/main/docs/checks.md`
- OpenSSF Best Practices Badge passing criteria:
  `https://www.bestpractices.dev/en/criteria/0`
- GitHub CODEOWNERS review routing:
  `https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners`
