# Strategic Gap Audit

Status: source-backed step-back audit for the current roadmap. This file does
not add CLI, MCP, JSON, fingerprint, schema, dependency, or network behavior.

Checked: 2026-08-13.

## Bottom Line

The project has a strong stable baseline: the CLI, JSON schema, local stdio MCP
server, bounded collectors, release path, generated-artifact guards, public
proof bundle, and claim-map gates are shipped. Stable infrastructure is not
proof that the product is complete. Evidence-semantic integrity and MCP v2
adoption are complete maintenance gates. The current product gaps are measured
utility, catalog quality, latency and degradation evidence, and agent context
and portability cost. Agent Plugins v1.0.0 and Open Knowledge Format v0.2 are
explicit interoperability inputs, but they do not displace the product-quality
order below.

The highest-value next build is not inference expansion. The aggregate-safe
product-quality baseline found that the frozen M365 ablation failed its
structural-identifiability preflight before target contact, so collecting
private labels cannot answer its promotion question. v2.12 applies
non-promotion through the compatible ADR-0013 transition. The v2.13 caller-held
observation capsule and ADR-0014 OKF v0.2 deferral are shipped. The next
operation is v2.14: the rank round is closed with its membership-bound
four-band aggregate, four bounded promoted families, explicit dispositions,
and a fixed-observation zero-regression decision. Freeze the regional contract
next, then execute regional, vendor-seed, and drift rounds with aggregate-only
evidence.
The claim audit and stable MCP matrix remain blocking regression
gates. Artifact review, OpenSSF process, independent replication, and archive
work remain worthwhile maintainer tracks, but they do not outrank product
truthfulness or measured user value.

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
- MCP 2026-07-28 release candidate, current documentation, and Python SDK history:
  <https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/>,
  <https://modelcontextprotocol.io/docs/getting-started/intro>, and
  <https://pypi.org/project/mcp/>
- Agent Plugins v1.0.0 working-draft specification and compatible-client list:
  <https://agent-plugins.org/specification> and
  <https://agent-plugins.org/compatible-clients>
- Agent Skills specification, which defines the portable `SKILL.md` component
  used by Agent Plugins:
  <https://agentskills.io/specification>
- Open Knowledge Format v0.2 specification, current v0.2 announcement, and the
  original v0.1 announcement:
  <https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md>
  <https://cloud.google.com/blog/products/data-analytics/okf-v0-2-adds-trust-signals/>
  and
  <https://cloud.google.com/blog/products/data-analytics/how-the-open-knowledge-format-can-improve-data-sharing/>
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

- On 2026-08-13, remote release readiness verified that GitHub Releases, PyPI,
  the v2.13.0 tag, and the repository's synchronized release version identify
  the same commit. A later checkout must not describe a version as published
  until its local and remote release gates pass.
- Local release readiness passed for the published source state.
- Remote release readiness passed for the published main branch and
  verifies required GitHub Actions checks, public Scorecard API freshness and
  code-owned control scores, PyPI wheel and sdist publication, and GitHub
  Release wheel, sdist, SBOM, and attestation export assets; it also verifies
  PyPI provenance for the release wheel and sdist. The current GitHub
  provenance check for the completed SBOM also passes for v2.13.0. The older
  historical evidence predates that subject expansion.
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
- Top-level dependencies are current under the locked resolver state. MCP
  production uses `>=2.0.0,<3`; the exact isolated matrix passes on stable
  v1.28.1 and stable v2.0.0, with v1.28.1 retained as the rollback pin.
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
| Evidence-semantic integrity | Derived observations and model-bound public-evidence values can be presented more strongly than their evidence supports. | The fail-closed audit covers all 27 default-claim families; all are complete, with no material runtime family carrying incomplete lineage. | Keep the audit and its semantic contract tests blocking; reopen this track for any uncovered or stronger claim surface. | Do not add new inference semantics while a known default claim lacks direct provenance. |
| MCP v2 compatibility | The final 2026-07-28 protocol and stable SDK contain breaking changes that must remain characterized. | Production adopted v2.0.0 on 2026-07-31; the exact stable v1.28.1 and v2.0.0 matrix passes, with one compatibility boundary, doctor discovery selection, and conservative cache hints implemented. | Keep both stable pins blocking and treat any future major-version adoption as a separate release decision. | Do not couple remote MCP scope to compatibility maintenance. |
| Measured product utility | Green gates and sophisticated models do not establish that the output improves an operator decision. | The network-free scorecard and stable-v1 live characterization are complete. The frozen M365 design failed its structural-identifiability preflight before target contact: A1 equals A0, A2 equals A3, and A3 is dominated by A0. The declared live window is cancelled. v2.12 records fusion as an advanced diagnostic and begins the compatible explicit-flag transition. | Keep ADR-0013 blocking and require a new candidate plus executable identifiability preflight before any future real-domain fusion study. | Do not expand graph or probabilistic machinery without measured benefit. Do not collect when the promotion condition is structurally unreachable. |
| Catalog quality and freshness | A large catalog can grow coverage and false positives at the same time. | The catalog has 864 entries and 1,075 detections. One frozen convenience-sample baseline covers every bounded path, a 366-namespace unseen vertical holdout exercised every new rule without post-holdout tuning, and the independent rank round is closed with a membership-bound aggregate, explicit dispositions, and zero regression on fixed observations. The legacy date backlog and independent regional and vendor-seed strata plus the frozen drift sample remain open. | As the v2.14 priority, freeze and run the regional contract next, then vendor-seed and drift rounds, and backfill dates only in reviewed families. Freeze every remaining round's question, independent stratum or frozen prior sample for drift, observation opportunities, catalog and code digests, acceptance budget, and aggregate-only disclosure before collection. | No new undated or untested rule. No population claim from the convenience sample and no broad coverage claim while a bounded path or named stratum is unmeasured. |
| Latency and degradation contract | CT and external providers dominate long tails, while one instrumented convenience-sample run cannot establish product SLOs. | The dated aggregate-only live memo measures paired CT/no-CT resolver latency, primary-source stages, merge replay, inference, rendering, allocation, loop lag, degradation, warm disk, and warm MCP bytes without target rows. It completed 50 of 50 no-CT rows and 47 of 50 CT rows; concurrent CPU contention and heavy CT rate limiting keep p50/p95 values diagnostic. | Run a clean-machine, stage-specific follow-up before setting budgets or moving work to threads; keep the independent schema gate blocking and apply stable-v2 deltas from the completed MCP matrix separately. | Move only proven blocking I/O and do not create brittle timing CI. |
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
| 2. Freeze and run distinct catalog rounds - **active v2.14 priority** | Before collection, freeze the question, independent input stratum or frozen prior sample for drift, eligibility and deduplication unit, observation opportunities and options, catalog and code digests, measures, promotion and regression budgets, and disclosure-safe outputs. Then execute rank-band, regional, vendor-seed, and drift rounds in [catalog-strategy.md](catalog-strategy.md). | Per-round immutable contracts, private manifests, and aggregate before-and-after reports by record type, with unresolved, unavailable, unmeasured, promoted, rejected, and deferred counts. Every promoted rule has a provider reference or disclosure-safe basis, a date, a fictional positive fixture, a lookalike negative, and a claim boundary. | A repeated list is a drift round, not new coverage. Stop when survivors lack an independent basis, fail a negative fixture, or exceed the frozen regression budget. |
| 3. Evaluate agent utility | Use representative tasks for single-domain summary, explanation, posture gaps, comparison, and catalog lookup. Compare the current deterministic 22-tool discovery surface with the smallest task-specific candidate only after freezing success, error, latency, and context-byte measures. Evaluate a schema-pinned Agent Plugins package as a packaging path separate from tool-surface size. | Task completion, unsupported-claim rate, correct tool selection, round trips, discovery bytes, result bytes, failure recovery, and portable-package discovery and launch across representative clients. | Do not add a core profile or hide tools merely because the payload is large. Do not claim Agent Plugins conformance before pinned-schema and client evidence. Simplify only when task outcomes improve without reducing discoverability or compatibility. |
| 4. External usability proof | Ask an outside user to install from the released package, run the public smoke path, complete one explanation task, and follow the safe contribution path on a clean machine. | Aggregate outcome notes, time-to-first-result, confusing-step count, and fixes reproduced with fictional data. | Do not call maintainer reruns independent replication, and do not publish the user's targets or output. |
| 5. Consolidate later surface decisions | Fusion is decided in v2.11 and applied in v2.12. Use the later catalog and agent measurements to decide which remaining catalog and MCP presentation changes ship, then batch accepted work into coherent releases. | Decision memos with raw aggregate counts and bounds, preserved stable contracts, current release proof, and an updated roadmap that removes completed work. | An inconclusive result remains inconclusive. Retire complexity that cannot beat the simpler comparator on a named outcome. |

## Priority Order

1. Keep the completed trust foundation, claim audit, and freshness gates green.
2. Keep the completed MCP v1 and v2 compatibility matrix blocking.
3. Keep the completed stable-v1 resolver, allocation, degradation, CT-value,
   MCP-result, and independent schema characterizations blocking.
4. Keep the unused sampling-frame definition and private-frame digest immutable
   as historical evidence. Keep its cancelled design from contacting targets.
5. Keep the completed v2.12 non-promotion transition and its v3 default-off
   boundary explicit before later surface promotion.
6. Keep the shipped v2.13 caller-held observation capsule, four-way comparison,
   ADR-0014 OKF v0.2 deferral, and release proof blocking without replacing
   versioned JSON.
7. Preserve the closed v2.14 rank-round decision, then freeze and execute the
   regional, vendor-seed, and drift contracts with independent strata or the
   frozen prior sample for drift, aggregate-only outputs, fixtures, and explicit
   dispositions before broad catalog growth.
8. Use the resulting catalog evidence to inform later dimensioned email
   observations and agent-surface simplification; apply stable-v2 SDK
   characterization deltas from the completed MCP matrix.
9. Keep main clean, CI green, release readiness passing, and PyPI and GitHub
   release state and provenance aligned.
10. Run the paper claim freeze, OpenSSF questionnaire, outside replication, and
   archive decision as separate maintainer work when their external event is
   ready.

## Decision

v2.13 is shipped: the caller-held observation capsule, four-way classified
comparison, separate schema, and ADR-0014 OKF v0.2 deferral passed full,
protected-main, publication, provenance, and channel-parity gates without
replacing stable JSON. The current execution work is the v2.14 catalog quality
loop. The rank round is closed with its membership-bound stratified result and
explicit candidate dispositions. The regional contract is next; each remaining
regional, vendor-seed, and drift contract must be fixed before collection and
must end in aggregate evidence plus explicit candidate dispositions. v2.12 has
already applied the v2.11 structural stop
through the compatible ADR-0013 transition. Private labeled-row collection
under the cancelled design is prohibited.
Evidence integrity and MCP compatibility remain maintenance gates, not unfinished
feature tracks. Runtime expansion, broad catalog growth, stable-surface
promotion, and public real-data release remain blocked until a concrete
consumer, measured benefit, support tier, or architecture review changes the
value calculation.

Public status surfaces should continue to name absent external events as gaps.
Do not add Zenodo archive badges, DOI links, OpenSSF Best Practices project
links, reviewed-PR completion language, contributor-diversity claims, or outside
replication completion language until the corresponding event actually exists.
