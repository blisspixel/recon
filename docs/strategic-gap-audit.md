# Strategic Gap Audit

Status: source-backed step-back audit for the current roadmap. This file does
not add CLI, MCP, JSON, fingerprint, schema, dependency, or network behavior.

Checked: 2026-06-29.

## Bottom Line

The project has made real progress. The current phase is not runtime expansion.
For the current roadmap, recon is feature-complete: the CLI, JSON schema, MCP
server, release path, generated-artifact guards, public proof bundle, and
claim-map gates are shipped. The highest-value work is now hardening, polish,
artifact review readiness, OpenSSF process posture, and conservative research
refinement.

That does not mean the project is finished forever. It means the next changes
should improve trust, clarity, reproducibility, and false-positive control
before adding surface area.

## Sources Checked

- ACM artifact review and badging:
  <https://www.acm.org/publications/policies/artifact-review-and-badging-current>
- OpenSSF Scorecard checks:
  <https://github.com/ossf/scorecard/blob/main/docs/checks.md>
- OpenSSF Best Practices Badge criteria:
  <https://www.bestpractices.dev/en/criteria/0>
- SLSA v1.2 specification:
  <https://slsa.dev/spec/v1.2/>
- GitHub artifact attestations:
  <https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations>
- PyPI Trusted Publishing and attestations:
  <https://docs.pypi.org/trusted-publishers/> and
  <https://docs.pypi.org/attestations/>
- arXiv submission and ancillary-file guidance:
  <https://info.arxiv.org/help/submit/index.html> and
  <https://info.arxiv.org/help/ancillary_files.html>
- Current DMARC protocol and reporting split:
  <https://www.rfc-editor.org/rfc/rfc9989.html>,
  <https://www.rfc-editor.org/rfc/rfc9990.html>, and
  <https://www.rfc-editor.org/rfc/rfc9991.html>
- GitHub and Zenodo archive metadata guidance:
  <https://docs.github.com/repositories/archiving-a-github-repository/referencing-and-citing-content>,
  <https://help.zenodo.org/docs/github/describe-software/citation-file/>,
  and <https://help.zenodo.org/docs/github/describe-software/zenodo-json/>
- Security-aware artifact evaluation research:
  <https://arxiv.org/abs/2605.06508>

## Current Evidence

- `v2.2.17` is current on GitHub Releases and PyPI.
- Local release readiness passes for the current local main branch.
- Remote release readiness passes for the current pushed main branch and
  verifies required GitHub Actions checks, public Scorecard API freshness and
  code-owned control scores, PyPI wheel and sdist publication, and GitHub
  Release wheel, sdist, SBOM, and attestation export assets; it also verifies
  PyPI and GitHub provenance for the release wheel and sdist.
- CI, secrets scan, Scorecard workflows, and the public Scorecard API pass on
  current main.
- Public proof is recorded in
  [2026-06-29-submission-freeze-local-proof.md](../validation/2026-06-29-submission-freeze-local-proof.md),
  and the final claim-audit refresh is recorded in
  [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md).
- `scripts/check_validation_hygiene.py` and release readiness confirm private
  validation run directories are not tracked.
- GitHub contributor history and current contributors are maintainer-only.
- Top-level dependencies are current under the locked resolver state, with MCP
  intentionally bounded to the stable v1 line until a reviewed v2 migration.
- Public DMARC references in comments, tests, and validation notes use the
  current RFC 9989 protocol specification and RFC 9990 aggregate-reporting
  split rather than the prior obsolete citation.

## What Is Not Missing

These are not active gaps for the current roadmap:

| Area | Why it is not a gap |
|---|---|
| Runtime features | The shipped CLI, MCP server, schema, batch, delta, posture, and explanation surfaces satisfy the current roadmap. |
| Public company data | No private corpus, real target list, per-domain result rows, or tenant IDs are tracked. Private run outputs may exist locally under ignored paths only. |
| Package release | Documentation and proof-memo refreshes do not require a new package release. Release when package behavior, public package metadata, or release artifacts change. |
| Broad validation claims | The claim map already blocks population-rate, frequentist-coverage, and independent-calibration overclaims. |
| Fingerprint expansion | No active public-source-backed candidate is waiting. New patterns need public documentation or disclosure-safe aggregate evidence. |

## Real Remaining Gaps

| Gap | Why it matters | Current state | Next action | Stop rule |
|---|---|---|---|---|
| OpenSSF Best Practices Badge | Scorecard marks this as absent until a real badge project exists. | Readiness evidence and the manual answer queue are documented in [openssf-posture.md](openssf-posture.md) and [openssf-badge-readiness.md](openssf-badge-readiness.md), but no badge is claimed. | Complete the questionnaire on `bestpractices.dev`, then link the real badge page. | Do not add a placeholder badge or claim a badge before the project exists. |
| Reviewed PR signal | Scorecard cannot credit review history on direct-main work. | CODEOWNERS exists and required checks protect main. | Use reviewed PRs for non-urgent work when another qualified reviewer is available. | Do not manufacture review history or contributor diversity. |
| Artifact archive and DOI | External papers are easier to cite and review when the exact artifact is archived. | GitHub release, PyPI release, citation metadata, SBOM, provenance, reproducible build recipe, and [archive-readiness.md](archive-readiness.md) exist. | Once the paper package freezes, choose a DOI path such as Zenodo or the venue supplement, then add metadata deliberately. | Do not add `.zenodo.json`, DOI language, or archive-badge language before the archive policy is chosen. |
| Independent public replication | ACM-style result validation is stronger when someone outside the maintainer path reruns the artifact. | Public smoke and paper profiles are runnable and recorded by the maintainer, and [replication-runbook.md](replication-runbook.md) now defines the clean-machine request, handoff packet, and safe outcome notes. | Ask an outside reviewer to run the public commands on a clean machine and record only aggregate outcome notes. | Do not represent private-corpus rows as externally reproduced. |
| Pre-submission claim freeze | The paper is now the highest-risk source of accidental overclaiming. | Draft, outline, claim map, artifact guide, final audit, and [submission-freeze-checklist.md](submission-freeze-checklist.md) are synchronized. | Before submission, run the freeze checklist and freeze wording against the claim map. | No new empirical language without an explicit support tier. |
| Consumer provenance recipe | Supply-chain controls are strong, but consumers need a short verification path. | [supply-chain.md](supply-chain.md) documents attestations, SBOM, reproducible builds, and a consumer verification quick path; remote release readiness now verifies Scorecard API freshness plus PyPI and GitHub provenance. | Keep the recipe current at each meaningful release. | Do not claim a SLSA level beyond implemented controls. |
| Future dataset release model | A public real-apex label set would change the disclosure risk model. | [public-label-snapshot-decision.md](public-label-snapshot-decision.md) defers this for the current submission. | Reopen only with a separate data-handling and architecture review. | Do not commit apex lists, organization names, tenant IDs, per-domain rows, or unsuppressed small strata. |

## Priority Order

1. Keep main clean, CI green, release readiness passing, and PyPI and GitHub
   release state and provenance aligned.
2. Run a final paper claim freeze before any external submission package.
3. Complete the OpenSSF Best Practices Badge questionnaire if a visible
   Scorecard lift is worth the process work.
4. Arrange one outside public-artifact replication pass.
5. Decide whether the frozen paper package needs a DOI-backed archive.
6. Resume pattern or motif work only when a reviewed, public-source-backed
   candidate appears.

## Decision

The next work remains hardening and external write-up readiness. Runtime
expansion, catalog growth, stable-surface promotion, and public real-data
release are all blocked until a concrete consumer, support tier, or architecture
review changes the value calculation.
