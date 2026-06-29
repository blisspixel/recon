# External Write-Up Plan

Status: active maintainer plan. This is not a runtime contract and does not add
CLI, MCP, JSON, fingerprint, or network behavior.

## Research Refresh

The current external-artifact standard points to a small set of concrete
requirements:

- ACM artifact review separates availability, functional evaluation, and result
  validation; the project should inventory the artifact, make the runnable path
  clear, and avoid implying validated results where only availability is proven
  ([ACM Artifact Review and Badging](https://www.acm.org/publications/policies/artifact-review-and-badging-current)).
- arXiv expects a topical, refereeable scientific contribution prepared to
  accepted scholarly standards, with supplementary files handled explicitly
  rather than hidden in the manuscript source bundle
  ([arXiv submission guidelines](https://info.arxiv.org/help/submit/index.html),
  [arXiv ancillary files](https://info.arxiv.org/help/ancillary_files.html)).
- CFF and GitHub citation guidance make `CITATION.cff` the repository-root
  citation metadata source for software. The metadata needs to track the
  released version and release date because GitHub and archive integrations use
  it to show citation suggestions
  ([Citation File Format](https://citation-file-format.github.io/),
  [GitHub citation files](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-citation-files)).
- GitHub and Zenodo guidance treat GitHub releases as the handoff point for
  durable archival identifiers. Zenodo can mint a DOI per GitHub release for a
  public repository, but this project should not add `.zenodo.json` until the
  release metadata policy is intentional
  ([GitHub referencing and citing content](https://docs.github.com/repositories/archiving-a-github-repository/referencing-and-citing-content),
  [Zenodo CITATION.cff guidance](https://help.zenodo.org/docs/github/describe-software/citation-file/)).
- FAIR guidance applies to software, workflows, and data products: artifacts
  should be findable, accessible, interoperable, and reusable, with clear
  provenance and reuse terms
  ([GO FAIR principles](https://www.go-fair.org/fair-principles/)).
- NIST SP 800-188 frames public data release as a disclosure-risk problem that
  needs governance, documented controls, and a clear release model. For recon,
  that means private corpus rows stay private and the paper can cite only
  public, synthetic, or aggregate-safe artifacts
  ([NIST SP 800-188](https://csrc.nist.gov/pubs/sp/800/188/final)).
- SLSA, GitHub artifact attestations, PyPI attestations, and PEP 740 point to a
  source-to-artifact provenance story rather than an informal "trust me"
  release story. recon can document signed provenance and reproducible builds,
  but should not claim a SLSA level beyond the implemented release controls
  ([SLSA specification](https://slsa.dev/spec/),
  [GitHub artifact attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds),
  [PyPI attestations](https://docs.pypi.org/attestations/),
  [PEP 740](https://peps.python.org/pep-0740/)).
- MCP security guidance treats tool descriptions, tool outputs, and connected
  agents as trust boundaries. For recon's paper artifact, that means the MCP
  story stays least-privilege, local-stdio, approval-aware, and clear that
  source-derived content is data, not instructions
  ([MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)).

## Current State

- The certificate-transparency validation cohort is closed as a bounded,
  maintainer-local, aggregate-only track. It proved the path, retry accounting,
  provider ceiling, candidate triage, and publication controls; it did not
  prove complete certificate-transparency coverage.
- `docs/paper-outline.md` and `docs/paper-draft.md` exist, and the initial claim
  map now lives in [paper-claim-map.md](paper-claim-map.md). Draft claims stay
  limited to the support tier recorded there.
- `python -m validation.reproduce_paper_numbers` is the public no-private-data
  reproduction entry point. The smoke profile gives a quick orchestrator check;
  the paper profile runs the public synthetic and proof bundle.
- [artifact-review.md](artifact-review.md) is the reviewer-facing command path
  for the public artifact, including what can and cannot be reproduced outside
  the private corpus.
- [paper-figures.md](paper-figures.md) defines the aggregate-safe SVG figure
  package and its regeneration command.
- [public-label-snapshot-decision.md](public-label-snapshot-decision.md)
  records why a frozen real-apex label snapshot is deferred under the current
  data-handling policy and closes the public-list sampling path for this
  submission as a robustness check rather than a population-rate claim.
- The 2026-06-26 smoke check with stamp `publication-plan-smoke-20260626`
  passed all five public steps and reported `Private corpora read: no`.
- The 2026-06-28 smoke check with stamp `hybrid-interval-smoke-20260628`
  passed all five public steps after the hybrid credible-interval change and
  reported `Private corpora read: no`.
- The 2026-06-28 full public proof check with stamp
  `hybrid-interval-paper-20260628` passed all five public steps after the hybrid
  credible-interval change and reported `Private corpora read: no`.
- The 2026-06-28 full public proof check with stamp
  `adversarial-perturbation-paper-20260628` passed all five public steps after
  the adversarial add/remove perturbation harness change and reported
  `Private corpora read: no`. The aggregate-only memo is
  [2026-06-28-adversarial-perturbation-paper.md](../validation/2026-06-28-adversarial-perturbation-paper.md).
- The 2026-06-28 final claim audit smoke check with stamp
  `discussion-claim-audit-smoke-20260628` passed all five public steps after
  the discussion and conclusion claim-tier tightening and reported
  `Private corpora read: no`.
- The 2026-06-28 final claim audit full public proof check with stamp
  `discussion-claim-audit-paper-20260628` passed all five public steps and
  reported `Private corpora read: no`. The aggregate-only memo is
  [2026-06-28-final-claim-audit.md](../validation/2026-06-28-final-claim-audit.md).
- The 2026-06-29 final claim audit refresh smoke check with stamp
  `metric-lineage-claim-audit-smoke-20260629` passed all five public steps after
  the metric-lineage wording refresh and reported `Private corpora read: no`.
- The 2026-06-29 final claim audit refresh full public proof check with stamp
  `metric-lineage-claim-audit-paper-20260629` passed all five public steps and
  reported `Private corpora read: no`. The aggregate-only memo is
  [2026-06-29-final-claim-audit-refresh.md](../validation/2026-06-29-final-claim-audit-refresh.md).
- `CITATION.cff` is the citation metadata source and release readiness now
  checks it against `pyproject.toml` and the current `CHANGELOG.md` release
  section.
- The 2026-06-28 private aggregate calibration refresh now reports both legacy
  fixed-bin ECE and equal-mass, mean-confidence ECE with deterministic bootstrap
  CI in the committed aggregate memo.
- Private corpus calibration remains maintainer-local. Public artifacts may
  include aggregate counts, rates, intervals, and suppressed-cell statements
  only.
- The M365 independent-instrument decision is closed for this submission:
  [m365-tenancy-decision.md](m365-tenancy-decision.md) records why no passive
  instrument is independent enough to promote the result beyond channel-split
  corroboration.
- The final claim audit is complete and refreshed for the current draft package
  after the metric-lineage wording update. Any future experiment, paper wording,
  package, or claim-map change must rerun the final claim audit before
  submission packaging.
- The discussion and conclusion now reflect the June 28 aggregate refresh
  without promoting it beyond the claim map: no clean independent calibration
  result, DMARC residual negative, M365 corroboration only, and Google Workspace
  one-sided recall only.

## What Is Next And Why

The next highest-leverage work is external write-up readiness, not new runtime
behavior.

Reasoning:

1. The certificate-transparency retry loop is closed. More live retries would
   mostly measure public CT provider pacing again unless a new provider path or
   validation question appears.
2. Fingerprint and motif triage has no active public-source-backed candidate
   after Session F. Catalog growth should resume only when a candidate has
   stable public documentation or repeated aggregate evidence plus negative
   tests.
3. Surface inventory promotion is blocked by the roadmap's consumer gate. No
   concrete external consumer currently needs a stable subset.
4. The assurance, validation, release, citation, and public-reproduction pieces
   are now strong enough to package for outside review. That work improves trust
   without widening the passive collection surface.
5. The public-list sampling question is closed for this submission by keeping
   public-list numbers as robustness checks rather than population rates. A
   future population-rate claim would require a new data-handling and
   architecture review.

## Codebase Constraints

- Do not add a command, MCP tool, schema field, fingerprint, motif, CPT change,
  dependency, paid API, or new network source for the write-up package.
- Keep public examples fictional or synthetic.
- Keep private corpus identifiers out of committed docs and artifacts: no real
  apexes, organization names, tenant IDs, per-domain rows, or unsuppressed small
  strata.
- Claims about the Bayesian intervals must distinguish reference calibration,
  synthetic evidence-responsiveness, and structural guarantees. Do not claim
  frequentist coverage for unlabeled nodes.
- Use existing gates: `scripts/check.py`, validation hygiene, text hygiene,
  markdown links, and release readiness.

## Execution Plan

1. **Metadata guard.** Keep `CITATION.cff` synchronized with the project version
   and changelog release date through `scripts/release_readiness.py`.
2. **Orientation refresh.** Point README, roadmap, docs index, validation docs,
   paper outline, current-state analysis, and the maintainer logs at this plan.
3. **Public artifact smoke.** Keep the smoke profile current. The current
   final audit run used
   `python -m validation.reproduce_paper_numbers --profile smoke --stamp metric-lineage-claim-audit-smoke-20260629`
   and kept outputs under ignored `validation/local/`.
4. **Full public proof.** Keep the paper profile current. The current final
   audit run used
   `python -m validation.reproduce_paper_numbers --profile paper --stamp metric-lineage-claim-audit-paper-20260629`
   before treating the public proof bundle as current for submission.
5. **Artifact guide.** Keep [artifact-review.md](artifact-review.md) current with
   the exact public reviewer commands and their claim boundaries.
6. **Claim map.** Keep [paper-claim-map.md](paper-claim-map.md) current as each
   paper claim moves between code invariant, unit or property test, public
   reproduction harness, public validation memo, aggregate-only private memo, or
   requires-more-evidence status.
7. **Draft tightening.** Update `docs/paper-outline.md` and
   `docs/paper-draft.md` only where the claim map proves the text. Mark
   unresolved empirical cells as pending rather than smoothing over them.
8. **Figure package.** Keep [paper-figures.md](paper-figures.md) and
   `docs/assets/paper/*.svg` generated from committed aggregate-safe sources
   through `scripts/generate_paper_figures.py --check`.
9. **Snapshot and sampling decision.** Keep the public label snapshot deferred,
   and keep public-list numbers as robustness checks rather than population
   rates, unless a separate data-handling and architecture review approves a
   new release model.
10. **M365 decision.** Keep [m365-tenancy-decision.md](m365-tenancy-decision.md)
   linked from the paper package and keep the tenancy result named as
   corroboration unless a new architecture review approves a stronger
   instrument.
11. **Final claim audit.** Re-run claim-map tests, figure drift check, public
   proof smoke, full public proof, the local gate, and release readiness after
   any paper or package change that could move a claim boundary.
12. **Release gate.** Run focused tests, hygiene checks, `scripts/check.py`, and
   remote release readiness after push.

## Acceptance Criteria

- `CITATION.cff` matches the current project version and changelog release date,
  and release readiness fails if it drifts.
- README and roadmap identify external write-up readiness as the active next
  work and link here.
- The docs index exposes this plan under Research.
- The artifact review guide gives exact public commands and separates public
  result validation from private aggregate evidence.
- The public reproduction smoke profile completes from the current checkout.
- The full public proof profile completes from the current checkout before
  submission packaging cites the synthetic and model-internal proof rows.
- The final claim audit memo links the public smoke run, full public proof run,
  claim-map audit, figure drift check, local gate, and release readiness for the
  current draft package.
- The claim map links every Section 6 empirical row to a support tier and source.
- The figure package regenerates deterministically and contains only
  aggregate-safe source data.
- No committed artifact contains private target identifiers or raw private
  result rows.
- The paper package links the public label snapshot decision and does not
  promise a frozen real-apex list.
- Public-list numbers are framed as robustness checks rather than population
  rates.
- M365 tenancy evidence is framed as corroboration, and
  [m365-tenancy-decision.md](m365-tenancy-decision.md) explains why no passive
  independent instrument is adopted for this submission.
- No runtime surface changes.
- Local gate passes, with coverage above the configured floor.
