# Paper Claim Map

Status: active external-write-up control. This file maps draft claims to the
highest evidence tier recon can honestly claim today. It does not add runtime,
schema, MCP, fingerprint, network, or release behavior.

## Evidence Tiers

| Tier | Meaning | Publication rule |
|---|---|---|
| Invariant | A design boundary enforced by code structure, tests, or release gates | May be stated as a system property when the named gate is green |
| Public proof harness | Runnable from a clean checkout without private corpora or network targets | May be called reproducible by outside reviewers |
| Public validation memo | Committed aggregate or synthetic memo with no target identifiers | May be cited directly with the memo date and scope |
| Aggregate-only private memo | Maintainer-local corpus result reduced to disclosure-safe aggregates | May be cited as maintainer-reproduced aggregate evidence only |
| Requires further evidence | The draft claim is not supported strongly enough yet | Must stay caveated or remain out of the external submission |

## Artifact Review Boundary

Current artifact guidance separates several claims that are easy to blur:
availability, functional evaluation, reusability, and result validation. recon
therefore uses these boundaries for the write-up package:

- Availability: the repository, license, README, docs index, schema, release
  changelog, and citation metadata are public and versioned.
- Functional evaluation: a reviewer can install from source and run
  `python -m validation.reproduce_paper_numbers` or the smoke profile without
  private corpora.
- Result validation: only rows backed by the public proof bundle or public
  validation memos are externally reproducible. Private-corpus aggregate rows
  are disclosure-safe evidence, not independently reproducible results.
- Reusability: CLI, JSON schema, MCP docs, operational contract, data-handling
  policy, and supply-chain docs must be enough for a reviewer to run, inspect,
  and cite the artifact without private maintainer context.
- Published artifact integrity: after `main` and the current version are public,
  `scripts/release_readiness.py --remote` checks that required GitHub Actions
  runs passed, the public Scorecard API reports the exact `HEAD` and the
  expected code-owned controls, and PyPI plus the GitHub Release expose the
  exact wheel, sdist, completed SBOM, and attestation export. It verifies PyPI
  provenance, requires the remote and local current version tag plus `HEAD` to
  identify one commit, and binds required GitHub subjects to the exported
  bundle, release workflow, source tag and commit digest, and hosted-runner
  boundary. Releases
  produced by the current workflow require the wheel, sdist, and completed
  SBOM; the exact v2.6.3 historical exception requires its wheel and sdist plus
  completed SBOM structure validation. The gate also requires both distribution
  channels to expose identical wheel and sdist bytes. This is release-state
  evidence, not empirical result validation.

The most recent recorded public proof gate is the historical
[2026-06-30 submission-freeze local proof](../validation/2026-06-30-submission-freeze-local-proof.md).
The most recent recorded final claim audit is the historical
[2026-06-29 Scorecard-gate claim audit](../validation/2026-06-29-scorecard-gate-claim-audit.md).
They record a passing smoke run, full public proof run, claim-map audit, figure
drift check, local gate, and release-readiness check for the commits named in
those memos. The paper and package changed afterward, so the current draft is
unfrozen and neither memo proves the current tree. Rerun the complete submission
gate before external packaging.

This follows the artifact-review split in ACM badging guidance, arXiv's
supplementary-file model, NIST SP 800-188 disclosure-risk framing, CFF/GitHub
citation guidance, SLSA provenance guidance, PyPI attestation guidance, and MCP
security guidance:

- [ACM artifact review and badging](https://www.acm.org/publications/policies/artifact-review-and-badging-current)
- [arXiv submission guidelines](https://info.arxiv.org/help/submit/index.html)
- [arXiv ancillary files](https://info.arxiv.org/help/ancillary_files.html)
- [NIST SP 800-188](https://csrc.nist.gov/pubs/sp/800/188/final)
- [Citation File Format](https://citation-file-format.github.io/)
- [GitHub citation files](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-citation-files)
- [SLSA specification](https://slsa.dev/spec/)
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [PyPI attestations](https://docs.pypi.org/attestations/)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [MCP authorization specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

## Claim Map

| Draft claim | Current support | Source and gate | Allowed wording |
|---|---|---|---|
| recon is passive by default and zero credential | Invariant | [traceability-matrix.md](traceability-matrix.md), [legal.md](legal.md), `tests/test_passive_default.py`, `tests/test_server_instructions.py` | State as default behavior, naming the standard MTA-STS fetch and opt-in direct probes. |
| recon preserves provenance for conclusions | Invariant | [how-it-works.md](how-it-works.md), [schema.md](schema.md), `tests/test_explanation_engine.py`, `tests/test_explain_dag_top3.py` | State that the emitted reconstructed graph reports evidence reachability, disconnected terminals, and completeness diagnostics. Do not call this full or exact generation-time lineage for insight or posture associations reconstructed from rendered text or proxy rules, and do not claim that evidence proves operational truth. |
| Exact inference matches a full-latent-joint reference on the committed sweep | Public proof harness plus public validation memo | `validation/differential_verification.py`, `tests/test_bayesian_differential.py`, `python -m validation.reproduce_paper_numbers`, [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md) | State as agreement over the none/one/all cross-product plus exhaustive local subsets for three factor-heavy nodes under two backgrounds. Do not claim the global evidence power set was enumerated. |
| Suppression monotonicity is local to evidence removal under fixed positive-factor assumptions | Public proof harness | `validation/adversarial_properties.py`, `tests/test_adversarial_properties.py`, [correlation.md](correlation.md) section 3.4 | State only that deleting a fired unit cannot raise that node's local presence odds while the prior, parent context, dependence reduction, and all other evidence stay fixed. Do not claim movement toward 0.5, wider bands, global DAG robustness, or protection from planted indicators. |
| Planted evidence can move posteriors across the decision boundary | Public proof harness plus public validation memo | `validation/adversarial_properties.py`, `tests/test_adversarial_properties.py`, [2026-06-28-adversarial-perturbation-paper.md](../validation/2026-06-28-adversarial-perturbation-paper.md), [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md) | State as a synthetic model-internal perturbation measurement of the threat-model boundary. Do not state attacker prevalence, exploitability, or real-world false-positive rate. |
| The 80 percent uncertainty band contains selected CAL8 perturbed-model conditionals in the recorded finite experiment | Public proof harness plus public validation memo | `validation/interval_coverage.py`, `tests/test_interval_coverage.py`, [interval-coverage.md](../validation/interval-coverage.md), [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md) | State as finite model-internal scenario containment, not a credible interval, confidence interval, identification region, or general misspecification bound. |
| Posteriors are stable under +/-20 percent likelihood perturbation | Public proof harness plus public validation memo | `validation/likelihood_sensitivity.py`, `tests/test_calibration_metrics.py`, [cal8-likelihood-sensitivity.md](../validation/cal8-likelihood-sensitivity.md), [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md) | State as sensitivity to elicited likelihoods, not evidence of real-world calibration. |
| The Bayesian and graph layers have recorded behavior against simple baselines in tailored synthetic worlds | Public validation memo | `validation/layer_ablation.py`, `tests/test_layer_ablation.py`, [layer-ablation.md](../validation/layer-ablation.md), [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md) | State the actual mixed stress result. The observation sampler draws grouped bindings independently and can violate mutually exclusive or redundant group semantics, so do not call it model-generated truth, an MNAR-price estimate, or real product value. |
| DMARC full posterior agrees strongly with the DMARC record | Aggregate-only private memo | `validation/reference_calibration.py`, [reference-calibration.md](../validation/reference-calibration.md), [2026-06-28-full-corpus-calibration-refresh.md](../validation/2026-06-28-full-corpus-calibration-refresh.md) | State as in-sample, publisher-conditional DMARC-anchored consistency, not clean calibration. |
| DMARC-held-out residual is weak after label-input masking | Aggregate-only private memo | `validation/reference_calibration.py`, [public-list-calibration.md](../validation/public-list-calibration.md), [statistical-assurance.md](statistical-assurance.md) | State as a predictor-input-disjoint but parameter-development-overlapping negative diagnostic. Do not call it independent predictive validation. |
| DMARC-held-out residual collapse is explainable from the remaining signal strengths | Committed model data plus aggregate-only private memo | `src/recon_tool/data/bayesian_network.yaml`, [2026-06-28-full-corpus-calibration-refresh.md](../validation/2026-06-28-full-corpus-calibration-refresh.md), [statistical-assurance.md](statistical-assurance.md) | State as a diagnostic reading: after DMARC is masked, MTA-STS is too rare and strict SPF is too weak to recover the label. Do not state causal proof. |
| M365 tenancy DNS-only predictor corroborates provider attestation | Aggregate-only private memo | `validation/tenancy_reference_calibration.py`, `tests/test_tenancy_reference_calibration.py`, [public-list-calibration.md](../validation/public-list-calibration.md), [m365-tenancy-decision.md](m365-tenancy-decision.md) | State as channel-split corroboration with shared tenant-provisioning common-cause caveat. Do not state independent calibration. |
| Google Workspace tenancy has only a one-sided check | Aggregate-only private memo | `validation/tenancy_reference_calibration.py`, [public-list-calibration.md](../validation/public-list-calibration.md), [statistical-assurance.md](statistical-assurance.md) | State recall on attested positives only. Do not imply authoritative negatives. |
| Split-conformal logic is implemented; the current corpus artifact is a dependent re-split diagnostic | Aggregate-only private memo plus tested pure logic | `validation/conformal_coverage.py`, `tests/test_conformal_coverage.py`, [public-list-calibration.md](../validation/public-list-calibration.md) | State the future-point theorem only for a scorer trained independently of exchangeable calibration/test points. The recorded scorer reused development data, so its current row has no coverage guarantee. |
| Reliability-estimator assumptions are separated from model behavior | Invariant plus tested pure logic | `validation/calibration_estimators.py`, `tests/test_calibration_estimators.py`, `tests/test_reference_calibration.py`, [2026-06-28-full-corpus-calibration-refresh.md](../validation/2026-06-28-full-corpus-calibration-refresh.md) | Future private reruns use tie-preserving reliability for the discrete score support. No current tie-preserving numeric estimate is available. Label every committed ECE value as historical, identify index-sliced equal-mass numbers as legacy, and treat row bootstrap/Wilson intervals as naive-iid diagnostics with no coverage interpretation. |
| Entropy reduction field is a signed marginal entropy change; model-derived posture buckets are descriptive diagnostics | Public validation memo | `validation/posture_distributions.py`, `tests/test_posture_distributions.py`, [public-list-calibration.md](../validation/public-list-calibration.md), [public-label-snapshot-decision.md](public-label-snapshot-decision.md) | State as a selected public-list cross-check. The sum can double count dependent nodes and the posture buckets are construction-linked. Do not call it information leakage, hardening effect, or population behavior. |
| Per-vertical residual weakness appears across the curated publisher strata | Aggregate-only private memo | [2026-06-28-full-corpus-calibration-refresh.md](../validation/2026-06-28-full-corpus-calibration-refresh.md), [statistical-assurance.md](statistical-assurance.md) | State across the 22 disclosed, DMARC-publisher-conditional development strata only. Do not generalize beyond them. |
| The discussion and conclusion do not claim broad calibration | Aggregate-only private memo plus public claim audit | [2026-06-28-full-corpus-calibration-refresh.md](../validation/2026-06-28-full-corpus-calibration-refresh.md), [m365-tenancy-decision.md](m365-tenancy-decision.md), [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md) | State that recon has no training-disjoint, predictor-input-disjoint passing calibration result today; DMARC rows are in-sample agreement/negative diagnostics, M365 is corroboration, and Google Workspace is one-sided recall. |
| The public artifact is signed and provenance-linked; same-job build repeatability fixes uv and a hash-locked backend graph; PyPI and GitHub publication bytes must match | Invariant | [supply-chain.md](supply-chain.md), `scripts/release_readiness.py --remote`, `scripts/check_release_channel_parity.py`, `tests/test_release_workflow_contract.py`, `tests/test_release_channel_parity.py`, `tests/test_scorecard_posture.py` | State the bounded deterministic-build check, exact release evidence, and cross-channel publication parity. Do not claim that a fresh build on another environment will reproduce the same bytes or that empirical results were independently reproduced. |
| Public artifacts exclude target identifiers and private rows | Invariant | [data-handling-policy.md](data-handling-policy.md), `scripts/check_validation_hygiene.py`, `tests/test_validation_hygiene.py`, `tests/test_public_validation_memo.py` | State the disclosure control and its mechanical gates. Keep semantic review as a separate requirement. |

## Submission Gate

Before the external write-up can leave draft status:

1. Every claim in `docs/paper-draft.md` section 6 must appear in the table above.
2. Any aggregate-only private memo row must name a disclosure-reviewed committed
   memo, not only a draft paragraph.
3. Claims marked as requiring further evidence must be removed or caveated in
   the submission draft.
4. The public smoke bundle must pass:
   `python -m validation.reproduce_paper_numbers --profile smoke`.
5. The full public proof bundle must pass before submission packaging cites the
   synthetic and model-internal proof rows:
   `python -m validation.reproduce_paper_numbers --profile paper`.
6. The local gate must pass:
   `uv run python scripts/check.py`.
7. Release readiness must pass:
   `uv run python scripts/release_readiness.py --allow-dirty`.
8. After `main` and the current version are published, remote release readiness
   must pass:
   `uv run python scripts/release_readiness.py --remote`.
   This includes public Scorecard API freshness, pinned PyPI provenance
   verification, GitHub bundle verification bound to the exact workflow, tag,
   source digest, and hosted-runner boundary for the policy-required subjects,
   completed SBOM structure validation, and
   cross-channel byte parity for the published wheel and sdist.
9. The public-list sampling boundary must stay linked to
   [public-label-snapshot-decision.md](public-label-snapshot-decision.md):
   public-list numbers are robustness checks rather than population rates.
10. The most recent recorded final claim audit is the historical
    [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md).
    The current draft is unfrozen because later experiment, wording, package,
    and claim-map changes have not completed a new freeze audit. Rerun the audit
    after every such change and before submission.
