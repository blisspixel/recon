# Strategic Gap Audit

Status: source-backed step-back audit for the current roadmap. This file does
not add CLI, MCP, JSON, fingerprint, schema, dependency, or network behavior.

Checked: 2026-07-17.

## Bottom Line

The project has a strong stable baseline: the CLI, JSON schema, local stdio MCP
server, bounded collectors, release path, generated-artifact guards, public
proof bundle, and claim-map gates are shipped. Stable infrastructure is not
proof that the product is complete. The current product gaps are evidence
semantics, measured utility, catalog quality, latency and degradation evidence,
and MCP context and compatibility cost.

The highest-value work is not runtime expansion. It is correcting any default
claim that is stronger than its public evidence and establishing an
aggregate-safe product-quality baseline before adding more inference or graph
surface. The completed MCP candidate matrix now remains a blocking regression
and final-adoption gate. Artifact review, OpenSSF process, independent
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
  <https://modelcontextprotocol.io/development/roadmap>,
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
- GitHub public issue templates, public attachments, private vulnerability
  reporting, repository topics, and social preview guidance:
  <https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/about-issue-and-pull-request-templates>,
  <https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/attaching-files>,
  <https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-a-vulnerability/privately-reporting-a-security-vulnerability>,
  <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics>,
  and
  <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/customizing-your-repositorys-social-media-preview>.

## Current Evidence

- At the 2026-07-13 refresh, GitHub Releases and PyPI matched the repository's
  synchronized release version.
  A later checkout must not describe a version as published until its local and
  remote release gates pass.
- Local release readiness passed for the published source state.
- Remote release readiness passed for the published main branch and
  verifies required GitHub Actions checks, public Scorecard API freshness and
  code-owned control scores, PyPI wheel and sdist publication, and GitHub
  Release wheel, sdist, SBOM, and attestation export assets; it also verifies
  PyPI provenance for the release wheel and sdist. The next published release
  must additionally pass the current GitHub provenance check for the completed
  SBOM; the historical evidence predates that subject expansion.
- CI, secrets scan, Scorecard workflows, and the public Scorecard API passed on
  the published main branch. Any in-progress release checkout requires fresh
  local and remote evidence before publication.
- Historical public proof is recorded in
  [2026-06-30-submission-freeze-local-proof.md](../validation/2026-06-30-submission-freeze-local-proof.md),
  and the historical final claim-audit refresh is recorded in
  [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md).
  Later product, documentation, paper, and claim-map changes leave the current
  package unfrozen; those records are not current submission proof.
- `scripts/check_validation_hygiene.py` and release readiness confirm private
  validation run directories are not tracked.
- Public bug and fingerprint intake now requires a target-data acknowledgement.
  The forms accept reserved synthetic fixtures, sanitized diagnostics, provider names,
  provider-controlled service patterns, and provider documentation, but not
  evaluated-target identities, records, screenshots, or per-domain output.
- The product introduction now promises a Python package, CLI, versioned JSON,
  and local stdio MCP server. It no longer implies a documented top-level
  library facade that the package does not provide.
- New fingerprint detections now require a valid, non-future `verified` date in
  local and remote gates. The scaffold emits the date, normal YAML date values
  load correctly, and the first recently researched pattern family is dated.
  The older undated catalog remains an explicit backfill queue.
- GitHub contributor history and current contributors are maintainer-only.
- Top-level dependencies are current under the locked resolver state. MCP is
  intentionally bounded to `>=1.28.1,<2`; the exact isolated matrix passes on
  stable v1.28.1 and candidate v2.0.0b1, while final v2 adoption remains
  contingent on the final specification, stable SDK, and full release gate.
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
| MCP v2 compatibility | The final 2026-07-28 protocol and stable SDK are imminent and contain breaking changes. | The exact v1.28.1 and v2.0.0b1 matrix passes; one compatibility boundary, the truthful dependency floor, doctor discovery selection, and conservative cache hints are implemented. | Keep the matrix blocking, then rerun it against the final specification and stable v2 SDK before changing production. | Do not publish a prerelease dependency or add remote MCP scope. |
| Measured product utility | Green gates and sophisticated models do not establish that the output improves an operator decision. | No unified scorecard covers unsupported claims, abstention, provenance, catalog surface, CT marginal value, latency, degradation, or MCP context cost. | Establish an aggregate-safe baseline and predeclared deterministic-versus-fusion ablation. | Do not expand graph or probabilistic machinery without measured benefit. |
| Catalog quality and freshness | A large catalog can grow coverage and false positives at the same time. | The catalog has 855 entries and 1,062 detections. One frozen convenience-sample baseline covers every bounded path, and a 366-namespace unseen vertical holdout exercised every new rule without post-holdout tuning. The legacy date backlog and independent rank and regional strata remain open. | Add rank and regional rounds, backfill dates in reviewed families, and ratchet stale dates and negative fixtures. | No new undated or untested rule. No population claim from the convenience sample and no broad coverage claim while a bounded path or named stratum is unmeasured. |
| Latency and degradation contract | CT and external providers dominate long tails, while current published measurements are historical single runs. | Timeouts and partial results are bounded, but stage measurements and reproducible p50/p95 budgets are not established. | Run stable-v1 resolver and schema characterization before the product scorecard; apply only candidate-SDK deltas after the MCP matrix. | Move only proven blocking I/O and do not create brittle timing CI. |
| OpenSSF Best Practices Badge | Scorecard marks this as absent until a real badge project exists. | Readiness evidence and the manual answer queue are documented in [openssf-posture.md](openssf-posture.md) and [openssf-badge-readiness.md](openssf-badge-readiness.md), but no badge is claimed. | Complete the questionnaire on `bestpractices.dev`, then link the real badge page. | Do not add a placeholder badge or claim a badge before the project exists. |
| Reviewed PR signal | Scorecard cannot credit review history on direct-main work. | CODEOWNERS exists and required checks protect main. | Use reviewed PRs for non-urgent work when another qualified reviewer is available. | Do not manufacture review history or contributor diversity. |
| Artifact archive and DOI | External papers are easier to cite and review when the exact artifact is archived. | GitHub release, PyPI release, citation metadata, SBOM, provenance, a bounded same-job deterministic-build recipe, and [archive-readiness.md](archive-readiness.md) exist; the archive path decision packet now separates `CITATION.cff` sufficiency from `.zenodo.json` need. | Once the paper package freezes, choose a DOI path such as Zenodo or the venue supplement, then add metadata deliberately. | Do not add `.zenodo.json`, DOI language, or archive-badge language before the archive policy is chosen. |
| Independent public replication | ACM-style result validation is stronger when someone outside the maintainer path reruns the artifact. | Public smoke and paper profiles are runnable and recorded by the maintainer, and [replication-runbook.md](replication-runbook.md) now defines the clean-machine request, handoff packet, and safe outcome notes. | Ask an outside reviewer to run the public commands on a clean machine and record only aggregate outcome notes. | Do not represent private-corpus rows as externally reproduced. |
| Pre-submission claim freeze | The paper is now the highest-risk source of accidental overclaiming. | The [submission freeze checklist](submission-freeze-checklist.md) records that the package is unfrozen. The June proof and final audit are historical; later changes require a new package-specific gate. | Before submission, rerun the public proof, final claim audit, release readiness, and freeze checklist against the exact package. | No new empirical language without an explicit support tier, and no historical proof presented as current. |
| Consumer provenance recipe | Supply-chain controls are strong, but consumers need a short verification path. | [supply-chain.md](supply-chain.md) documents attestations, SBOM, the bounded deterministic-build check, and a consumer verification quick path; remote release readiness now verifies Scorecard API freshness plus PyPI and GitHub provenance. | Keep the recipe current at each meaningful release. | Do not claim cross-environment byte identity or a SLSA level beyond implemented controls. |
| Future dataset release model | A public real-apex label set would change the disclosure risk model. | [public-label-snapshot-decision.md](public-label-snapshot-decision.md) defers this for the current submission. | Reopen only with a separate data-handling and architecture review. | Do not commit apex lists, organization names, tenant IDs, per-domain rows, or unsuppressed small strata. |
| Release signal | Very small package releases make meaningful change harder for users to identify even when every release is reproducible. | The release machinery is strong, but release batching is not yet treated as a product signal. | Batch ordinary compatible work into one coherent release narrative; reserve immediate patch releases for urgent correctness, security, or packaging failures. | Documentation-only, planning-only, and repository-metadata changes do not trigger a package release. |

## Quality Proof Execution Plan

Exceptional here means that a user can tell what recon observed, why it said
it, where it abstained, how much of the bounded public surface it classified,
and whether the agent interface improved a real task. Catalog size, test count,
release count, and feature count are supporting facts, not outcomes.

| Phase | Work | Promotion evidence | Stop rule |
|---|---|---|---|
| 0. Trust foundation | Align public intake with the data policy, correct public product promises, require verification dates on new detections, and align repository metadata with the current neutral product voice. | Required privacy acknowledgements, regression tests, a clean canonical gate, current repository description and topics, and green post-merge CI. | Do not start another broad catalog promotion while public intake asks for target data or a public promise lacks a maintained surface. |
| 1. Freeze the baseline | Run the stable-v1 latency, allocation, degradation, CT-value, provenance, catalog, and MCP payload measurements on a named catalog and code revision. Record unmeasured channels explicitly. | One dated aggregate-safe scorecard, reproduction commands, environment, revision digests, source-success counts, and no target rows. | Do not tune thresholds after reading the result, and do not publish a population interpretation for a convenience sample. |
| 2. Run distinct catalog rounds | Execute the baseline, rank-band, regional, vertical, vendor-seed holdout, and drift rounds in [catalog-strategy.md](catalog-strategy.md). Extend private unmatched-observation accounting from CNAME chains to apex CNAME, TXT, SPF, MX, NS, CAA, DMARC RUA, bounded owner-qualified TXT, and bounded SRV opportunities. | Per-round private manifests and aggregate before-and-after reports by record type, with unresolved, unavailable, unmeasured, promoted, rejected, and deferred counts. Every promoted rule has a provider reference or disclosure-safe basis, a date, a fictional positive fixture, a lookalike negative, and a claim boundary. | A repeated list is a drift round, not new coverage. Stop when survivors lack an independent basis, fail a negative fixture, or exceed the frozen regression budget. |
| 3. Evaluate agent utility | Use representative tasks for single-domain summary, explanation, posture gaps, comparison, and catalog lookup. Compare the current deterministic 22-tool discovery surface with the smallest task-specific candidate only after freezing success, error, latency, and context-byte measures. | Task completion, unsupported-claim rate, correct tool selection, round trips, discovery bytes, result bytes, and failure recovery across representative clients. | Do not add a core profile or hide tools merely because the payload is large. Simplify only when task outcomes improve without reducing discoverability or compatibility. |
| 4. External usability proof | Ask an outside user to install from the released package, run the public smoke path, complete one explanation task, and follow the safe contribution path on a clean machine. | Aggregate outcome notes, time-to-first-result, confusing-step count, and fixes reproduced with fictional data. | Do not call maintainer reruns independent replication, and do not publish the user's targets or output. |
| 5. Promote or retire | Use the predeclared product-quality and ablation rules to decide which inference, graph, catalog, and MCP features remain primary. Batch the accepted work into a coherent release. | Decision memo with raw aggregate counts and bounds, preserved stable contracts, current release proof, and an updated roadmap that removes completed work. | An inconclusive result remains inconclusive. Retire complexity that cannot beat the simpler comparator on a named outcome. |

## Priority Order

1. Complete the trust foundation and keep its intake and freshness gates green.
2. Correct bounded default-claim semantics and define the provenance ADR scope.
3. Run the stable-v1 resolver, allocation, CT-value, and schema
   characterization that feeds product measurement.
4. Complete the product-quality scorecard and freeze the ablation decision rule
   before running it.
5. Use the baseline to decide dimensioned email observations, catalog
   priorities, and agent-surface simplification; apply candidate-SDK
   characterization deltas after the MCP matrix.
6. Keep the MCP beta matrix blocking and repeat it against the final protocol
   and stable v2 SDK before changing the production dependency.
7. Keep main clean, CI green, release readiness passing, and PyPI and GitHub
   release state and provenance aligned.
8. Run the paper claim freeze, OpenSSF questionnaire, outside replication, and
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
