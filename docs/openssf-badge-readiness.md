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

This map prepares evidence for the passing-level questionnaire. The repository
[.project.d/bestpractices.json](../.project.d/bestpractices.json) proposes answers to all 67 current
passing criteria using the service's [documented import format](https://github.com/coreinfrastructure/best-practices-badge/blob/main/docs/bestpractices-json.md).
Unknown (`?`) answers are ignored by the service and require maintainer review.
This file does not register a project, authenticate to the service or attest
to a maintainer's knowledge or response history.

The 2026-10-20 evidence review proposes 53 `Met`, 3 `N/A` and 11 unknown
answers. These are import proposals, not a badge result or completion percentage.
The cryptography answers cite the shared transport, optional remote adapter,
[HTTPX's SSL documentation](https://www.python-httpx.org/advanced/ssl/) and
[Python's SSL defaults](https://docs.python.org/3.11/library/ssl.html#ssl.SSLContext).
The latter documents forward secrecy, minimum key sizes and security level 2
since Python 3.10, below recon's supported minimum. These default-client claims
do not establish the configuration of custom Python builds or operator-managed
TLS ingress for the optional remote container.

| Criteria area | Local evidence | Current answer posture |
|---|---|---|
| Basics | README, Apache-2.0 license, public repository, PyPI package metadata, release tags, changelog, and documented install path. | Ready to answer from committed docs and package metadata. |
| Change control | SemVer policy, `CHANGELOG.md`, release process, protected `main`, required checks, CODEOWNERS, and tagged releases. | Ready for checked PR wording; do not imply independent approval of maintainer-authored PRs. |
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

## Manual Answer Queue

The passing-level criteria mix repository-file facts with live process facts.
Before submitting the questionnaire, collect this queue in the real
`bestpractices.dev` project UI and keep each answer tied to public evidence:

| Criterion family | What must be checked manually | Acceptable answer boundary |
|---|---|---|
| Project sites and discussion | Repository, package, documentation, issue, and download URLs use HTTPS and remain publicly reachable. | Cite the live HTTPS URLs; do not infer reachability from local files. |
| Contribution process | Public contribution instructions describe how changes are proposed and what standards apply. | Cite `CONTRIBUTING.md` and the current checked-PR boundary; do not imply independent approval of maintainer-authored changes. |
| Issue and enhancement response history | Bug and enhancement reports from the prior 2-12 month window have enough public response history to answer honestly. | Use the public issue tracker state at submission time. The 2026-10-20 review found 26 issues, all maintainer-authored and closed; that is not an external response sample. Keep unknown when the applicable history cannot support an answer. |
| Vulnerability response history | Any vulnerability reports in the last 6 months were initially answered within the criteria window. | Cite `SECURITY.md` for process and answer the history question only from real report records. |
| Secure-development knowledge | The primary maintainer can honestly attest to secure design knowledge for this Python network-client tool. | Treat this as a maintainer attestation, not as evidence created by Scorecard or CI. |
| Cryptography applicability | recon uses verified TLS defaults and standard-library SHA-256; it does not implement cryptographic primitives. The optional remote adapter authenticates an operator-provided random bearer token or trusts platform ingress. | Default client TLS supports the key-length, working-algorithm, weakness and forward-secrecy proposals. Password-database N/A does not mean the remote adapter lacks authentication. Operator token generation and remote TLS ingress remain deployment responsibilities. |
| Static and dynamic analysis | CI, CodeQL, ruff, pyright, fuzzing, mutation, and tests are current for the release being described. | Cite public workflows and local gates; do not claim a third-party audit. |

Do not use this queue as a substitute badge record. It is a checklist for
answering the account-backed questionnaire, not a public claim that answers
were submitted.

## Remaining Unknown Answers

Each unknown in the import file names the evidence still needed. The remaining
11 answers fall into three groups:

- **Developer knowledge:** `know_secure_design` and `know_common_errors` require
  a primary developer's own attestation. Architecture documents and CI cannot
  provide that personal answer.
- **Response and disclosure history:** `report_responses`,
  `enhancement_responses`, `vulnerability_report_response`,
  `release_notes_vulns`, `vulnerabilities_fixed_60_days` and
  `vulnerabilities_critical_fixed` require the applicable reports, disclosure
  dates and released fixes. Check private email and private reports for the
  six-month vulnerability-response question. An empty public advisory list
  does not establish that no report was received.
- **Finding dispositions and credentials:** `static_analysis_fixed`,
  `dynamic_analysis_fixed` and `no_leaked_credentials` require confirmation of
  finding history, timely fixes and credential handling. The 2026-10-20 live
  review found no open CodeQL, Dependabot or secret-scanning alerts. The three
  open Scorecard alerts concern repository process. These observations and
  passing fuzz or secret scans do not prove an absence of vulnerabilities or
  valid credentials outside scanner coverage. Never test a possible credential
  against a service to validate a questionnaire answer.

GitHub private vulnerability reporting was confirmed enabled on 2026-10-20.
[SECURITY.md](../SECURITY.md) links the private HTTPS form as well as email.
The `dynamic_analysis_unsafe` N/A proposal concerns project-owned code: recon
ships a pure-Python universal wheel, with no project-owned memory-unsafe native
extension. It does not describe the language or safety of third-party runtimes
or dependencies. Python parser fuzzing still runs with the address sanitizer.

## Answers That Need Care

Some answers must stay precise:

- Reviewed changes: CODEOWNERS, strict checks and PRs are required, with no
  bypass actors. Stale approvals are dismissed and review threads must resolve.
  An independent approving reviewer is not currently available; automated checks
  and author self-review do not count as a second human approval.
  Do not claim a mandatory reviewed-PR process: required PRs and checks do not
  establish independent approval.
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
7. Push and verify GitHub CI, Secrets scan, and Scorecard.
8. Run `uv run python scripts/release_readiness.py --remote` only if the exact
   commit is also the published current-version tag.

## Stop Rules

- No badge link until the real badge project exists.
- No placeholder URL.
- No claim that a badge is "in progress" as a substitute for the public page.
- No answer that depends on private corpora, target lists, tenant IDs,
  per-domain findings, or unsuppressed small strata.
- No artificial contributors or manufactured review history.
