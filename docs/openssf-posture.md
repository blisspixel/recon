# OpenSSF Posture

This note records the current OpenSSF path for recon. It is intentionally
separate from the public Scorecard badge: Scorecard is an automated signal,
while the Best Practices Badge is an account-backed project questionnaire.

## Current Snapshot

- Date checked: 2026-06-30.
- Live API state at check time: public API rechecked after the
  submission-freeze proof refresh.
- Scorecard version: `v5.3.0`.
- Score: `7.5`.
- Public source: `https://api.securityscorecards.dev/projects/github.com/blisspixel/recon`.

The public API is authoritative for the exact commit behind the badge. Docs-only
commits can move `main` after a snapshot is written, so this file records the
reviewed posture and the live API URL rather than treating a commit hash as a
durable status promise. Remote release readiness queries that API for `HEAD`,
requires the current score floor, and fails if any code-owned control regresses
below `10`.

The code-owned controls are green: dangerous workflow patterns, dependency
update automation, token permissions, pinned dependencies, binary artifacts,
security policy, SAST, known vulnerabilities, packaging, fuzzing, signed
releases, and license all score `10`.

The remaining low or unknown checks are process-bound:

| Check | Current reason | Real next step |
|---|---|---|
| `Branch-Protection` | `main` is protected, but administrator bypass remains and PRs are not mandatory. | Keep the current required-check ruleset for clean-main work. If the project moves to a multi-maintainer flow, require PRs, remove administrator bypass, and require CODEOWNERS review. |
| `Code-Review` | No reviewed pull-request history exists for Scorecard to evaluate. | Use normal reviewed PRs for non-urgent work when there is another qualified reviewer. Do not manufacture review history. |
| `CI-Tests` | Scorecard did not find a pull request to inspect. | It will become meaningful once normal PRs exist. The local gate and `main` CI are already mandatory for direct mainline work. |
| `Maintained` | The repository is inside Scorecard's young-repository window. | Let age resolve naturally while keeping releases, CI, and security updates current. |
| `CII-Best-Practices` | No OpenSSF Best Practices Badge project is linked. | Use [openssf-badge-readiness.md](openssf-badge-readiness.md) to answer the questionnaire from committed evidence; link a badge only after the real project page exists and the answers match the repository. |
| `Contributors` | Scorecard sees no contributor diversity across organizations. | Accept this for a single-maintainer project. Do not add artificial contributors. |

## Best Practices Badge Readiness

The detailed worksheet lives in
[openssf-badge-readiness.md](openssf-badge-readiness.md). The OpenSSF Best
Practices Badge criteria are organized around basics, change control,
reporting, quality, security, and analysis. recon already has local evidence
for most passing-level questions:

| Area | Local evidence |
|---|---|
| Basics | README, Apache-2.0 license, PyPI package metadata, documented install and update path, public issue tracker, and stable project URLs. |
| Change control | Git history, SemVer policy, changelog, release process, tagged releases, signed provenance assets, and short-lived branch guidance. |
| Reporting | `SECURITY.md`, private vulnerability-reporting email, response timeline, issue templates, and no-real-company-data contribution policy. |
| Quality | `scripts/check.py` as the local CI mirror, branch coverage gate, mutation gate, property tests, fuzzing, golden renders, pyright strict mode, and generated-artifact drift guards. |
| Security | CodeQL, ruff security rules, `pip-audit`, secret scanning, push protection, least-privilege workflow tokens, pinned workflow actions, SBOM, reproducible builds, Trusted Publishing, PyPI attestations, and GitHub build provenance. |
| Analysis | Strict type checking, static analysis, workflow-pin checks, validation hygiene, text hygiene, schema drift checks, and release readiness checks. |

No OpenSSF Best Practices Badge is claimed in this repository until the project
exists on `bestpractices.dev` and the questionnaire is answered honestly from
the worksheet. A future badge link must point to the real project page and must
not be added as a placeholder.

## CODEOWNERS Decision

`.github/CODEOWNERS` routes all repository paths to `@blisspixel` so external
pull requests have clear ownership. This does not by itself create a
Scorecard-reviewed workflow. It is preparation for a future branch ruleset that
requires CODEOWNERS review if the project moves beyond single-maintainer direct
mainline work.

## Research Sources

- OpenSSF Scorecard check definitions:
  `https://github.com/ossf/scorecard/blob/main/docs/checks.md`
- OpenSSF Best Practices Badge passing criteria:
  `https://www.bestpractices.dev/en/criteria/0`
- GitHub CODEOWNERS review routing:
  `https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners`
