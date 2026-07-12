# Strategic Gap Audit

Status: source-backed step-back audit for the current roadmap. This file does
not add CLI, MCP, JSON, fingerprint, schema, dependency, or network behavior.

Checked: 2026-07-10.

## Bottom Line

The project has a strong stable baseline: the CLI, JSON schema, local stdio MCP
server, bounded collectors, release path, generated-artifact guards, public
proof bundle, and claim-map gates are shipped. Stable infrastructure is not
proof that the product is complete. The current product gaps are evidence
semantics, measured utility, catalog quality, latency and degradation evidence,
and MCP context and compatibility cost.

The highest-value work is not runtime expansion. It is correcting any default
claim that is stronger than its public evidence, characterizing the MCP v2 beta,
and establishing an aggregate-safe product-quality baseline before adding more
inference or graph surface. Artifact review, OpenSSF process, independent
replication, and archive work remain worthwhile maintainer tracks, but they do
not outrank product truthfulness or measured user value.

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
- MCP 2026-07-28 release candidate, draft tools, and Python SDK history:
  <https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/>,
  <https://modelcontextprotocol.io/specification/draft/server/tools>, and
  <https://pypi.org/project/mcp/>
- Python asyncio development guidance:
  <https://docs.python.org/3.14/library/asyncio-dev.html>
- JSON Schema 2020-12 validation:
  <https://json-schema.org/draft/2020-12/json-schema-validation>
- GitHub and Zenodo archive metadata guidance:
  <https://docs.github.com/repositories/archiving-a-github-repository/referencing-and-citing-content>,
  <https://help.zenodo.org/docs/github/describe-software/citation-file/>,
  and <https://help.zenodo.org/docs/github/describe-software/zenodo-json/>
- Security-aware artifact evaluation research:
  <https://arxiv.org/abs/2605.06508>

## Current Evidence

- At the 2026-07-10 audit, `v2.3.9` was current on GitHub Releases and PyPI.
- Local release readiness passes for the current local main branch.
- Remote release readiness passes for the current pushed main branch and
  verifies required GitHub Actions checks, public Scorecard API freshness and
  code-owned control scores, PyPI wheel and sdist publication, and GitHub
  Release wheel, sdist, SBOM, and attestation export assets; it also verifies
  PyPI and GitHub provenance for the release wheel and sdist.
- CI, secrets scan, Scorecard workflows, and the public Scorecard API pass on
  current main.
- Public proof is recorded in
  [2026-06-30-submission-freeze-local-proof.md](../validation/2026-06-30-submission-freeze-local-proof.md),
  and the final claim-audit refresh is recorded in
  [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md).
- `scripts/check_validation_hygiene.py` and release readiness confirm private
  validation run directories are not tracked.
- GitHub contributor history and current contributors are maintainer-only.
- Top-level dependencies are current under the locked resolver state, with MCP
  intentionally bounded to the stable v1 line until a reviewed v2 migration.
  Official Python SDK `2.0.0b1` shipped on 2026-06-30, so the isolated
  compatibility-spike trigger is now met.
- Public DMARC references in comments, tests, and validation notes use the
  current RFC 9989 protocol specification and RFC 9990 aggregate-reporting
  split rather than the prior obsolete citation.

## What Is Not Missing

These are not active gaps for the current roadmap:

| Area | Why it is not a gap |
|---|---|
| Baseline runtime surface | The shipped CLI, MCP server, schema, batch, delta, posture, and explanation surfaces provide a stable base. New surface is not the current priority. |
| Public company data | No private corpus, real target list, per-domain result rows, or tenant IDs are committed or published. Private corpus and run rows may exist only in the ignored local workspaces defined by the data-handling policy. |
| Package release | Documentation and proof-memo refreshes do not require a new package release. Release when package behavior, public package metadata, or release artifacts change. |
| Broad validation claims | The claim map already blocks population-rate, frequentist-coverage, and independent-calibration overclaims. |
| Broad fingerprint expansion | New patterns need public documentation or disclosure-safe aggregate evidence. A proposal enters the queue only with an exact record type, pattern, evidence basis, identifier, and disposition; vendor names alone are not backlog items. |

## Real Remaining Gaps

| Gap | Why it matters | Current state | Next action | Stop rule |
|---|---|---|---|---|
| Evidence-semantic integrity | Derived observations and model-bound public-evidence values can be presented more strongly than their evidence supports. | Parent-platform child-product inference, MCP score wording, and cross-renderer provider drift are corrected; remaining default claims still need a complete provenance audit. | Audit every default claim and correct the smallest evidence-to-claim paths while preserving stable JSON. | Do not add new inference semantics while a known default claim lacks direct provenance. |
| MCP v2 compatibility | The final 2026-07-28 protocol and stable SDK are imminent and contain breaking changes. | Stable v1.28.1 is locked; official v2 beta `2.0.0b1` is available for an isolated matrix. | Run the exact-pinned compatibility matrix and document migration actions, dependency floor, and rollback pin. | Do not publish a prerelease dependency or add remote MCP scope. |
| Measured product utility | Green gates and sophisticated models do not establish that the output improves an operator decision. | No unified scorecard covers unsupported claims, abstention, provenance, catalog surface, CT marginal value, latency, degradation, or MCP context cost. | Establish an aggregate-safe baseline and predeclared deterministic-versus-fusion ablation. | Do not expand graph or probabilistic machinery without measured benefit. |
| Catalog quality and freshness | A large catalog can grow coverage and false positives at the same time. | The catalog has 847 entries and optional `verified` metadata, but no active classified-surface or stale-rule regression budget. | Baseline by record type and stratum, then ratchet references, dates, and negative fixtures. | No new undated, unreferenced, or untested rule. |
| Latency and degradation contract | CT and external providers dominate long tails, while current published measurements are historical single runs. | Timeouts and partial results are bounded, but stage measurements and reproducible p50/p95 budgets are not established. | Run stable-v1 resolver and schema characterization before the product scorecard; apply only candidate-SDK deltas after the MCP matrix. | Move only proven blocking I/O and do not create brittle timing CI. |
| OpenSSF Best Practices Badge | Scorecard marks this as absent until a real badge project exists. | Readiness evidence and the manual answer queue are documented in [openssf-posture.md](openssf-posture.md) and [openssf-badge-readiness.md](openssf-badge-readiness.md), but no badge is claimed. | Complete the questionnaire on `bestpractices.dev`, then link the real badge page. | Do not add a placeholder badge or claim a badge before the project exists. |
| Reviewed PR signal | Scorecard cannot credit review history on direct-main work. | CODEOWNERS exists and required checks protect main. | Use reviewed PRs for non-urgent work when another qualified reviewer is available. | Do not manufacture review history or contributor diversity. |
| Artifact archive and DOI | External papers are easier to cite and review when the exact artifact is archived. | GitHub release, PyPI release, citation metadata, SBOM, provenance, reproducible build recipe, and [archive-readiness.md](archive-readiness.md) exist; the archive path decision packet now separates `CITATION.cff` sufficiency from `.zenodo.json` need. | Once the paper package freezes, choose a DOI path such as Zenodo or the venue supplement, then add metadata deliberately. | Do not add `.zenodo.json`, DOI language, or archive-badge language before the archive policy is chosen. |
| Independent public replication | ACM-style result validation is stronger when someone outside the maintainer path reruns the artifact. | Public smoke and paper profiles are runnable and recorded by the maintainer, and [replication-runbook.md](replication-runbook.md) now defines the clean-machine request, handoff packet, and safe outcome notes. | Ask an outside reviewer to run the public commands on a clean machine and record only aggregate outcome notes. | Do not represent private-corpus rows as externally reproduced. |
| Pre-submission claim freeze | The paper is now the highest-risk source of accidental overclaiming. | Draft, outline, claim map, artifact guide, final audit, and [submission-freeze-checklist.md](submission-freeze-checklist.md) are synchronized. | Before submission, run the freeze checklist and freeze wording against the claim map. | No new empirical language without an explicit support tier. |
| Consumer provenance recipe | Supply-chain controls are strong, but consumers need a short verification path. | [supply-chain.md](supply-chain.md) documents attestations, SBOM, reproducible builds, and a consumer verification quick path; remote release readiness now verifies Scorecard API freshness plus PyPI and GitHub provenance. | Keep the recipe current at each meaningful release. | Do not claim a SLSA level beyond implemented controls. |
| Future dataset release model | A public real-apex label set would change the disclosure risk model. | [public-label-snapshot-decision.md](public-label-snapshot-decision.md) defers this for the current submission. | Reopen only with a separate data-handling and architecture review. | Do not commit apex lists, organization names, tenant IDs, per-domain rows, or unsuppressed small strata. |

## Priority Order

1. Correct bounded default-claim semantics and define the provenance ADR scope.
2. Run the isolated MCP v2 beta compatibility matrix.
3. Run the stable-v1 resolver, allocation, CT-value, and schema
   characterization that feeds product measurement.
4. Complete the product-quality scorecard and freeze the ablation decision rule
   before running it.
5. Use the baseline to decide dimensioned email observations, catalog
   priorities, and agent-surface simplification; apply candidate-SDK
   characterization deltas after the MCP matrix.
6. Keep main clean, CI green, release readiness passing, and PyPI and GitHub
   release state and provenance aligned.
7. Run the paper claim freeze, OpenSSF questionnaire, outside replication, and
   archive decision as separate maintainer work when their external event is
   ready.

## Decision

The next work is evidence integrity, MCP compatibility, and measured product
quality. Runtime expansion, broad catalog growth, stable-surface promotion, and
public real-data release remain blocked until a concrete consumer, measured
benefit, support tier, or architecture review changes the value calculation.

Public status surfaces should continue to name absent external events as gaps.
Do not add Zenodo archive badges, DOI links, OpenSSF Best Practices project
links, reviewed-PR completion language, contributor-diversity claims, or outside
replication completion language until the corresponding event actually exists.
