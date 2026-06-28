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

The latest public proof gate for the current draft package is
[2026-06-28-final-claim-audit.md](../validation/2026-06-28-final-claim-audit.md).
It records the passing smoke run, full public proof run, claim-map audit, figure
drift check, local gate, and release-readiness check.

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
- [GitHub artifact attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
- [PyPI attestations](https://docs.pypi.org/attestations/)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)

## Claim Map

| Draft claim | Current support | Source and gate | Allowed wording |
|---|---|---|---|
| recon is passive by default and zero credential | Invariant | [traceability-matrix.md](traceability-matrix.md), [legal.md](legal.md), `tests/test_passive_default.py`, `tests/test_server_instructions.py` | State as default behavior, naming the standard MTA-STS fetch and opt-in direct probes. |
| recon preserves provenance for conclusions | Invariant | [how-it-works.md](how-it-works.md), [schema.md](schema.md), `tests/test_explanation_engine.py`, `tests/test_explain_dag_top3.py` | State that conclusions are traceable through evidence and explanation surfaces, not that evidence proves operational truth. |
| Exact inference matches a full-joint reference | Public proof harness plus public validation memo | `validation/differential_verification.py`, `tests/test_bayesian_differential.py`, `python -m validation.reproduce_paper_numbers`, [2026-06-28-final-claim-audit.md](../validation/2026-06-28-final-claim-audit.md) | State as inference-engine correctness over enumerable shipped configurations. |
| Suppression monotonicity holds for evidence removal | Public proof harness | `validation/adversarial_properties.py`, `tests/test_adversarial_properties.py`, [correlation.md](correlation.md) section 4.3 | State robust to evidence removal. Also state not robust to evidence addition or planted indicators. |
| Planted evidence can move posteriors across the decision boundary | Public proof harness plus public validation memo | `validation/adversarial_properties.py`, `tests/test_adversarial_properties.py`, [2026-06-28-adversarial-perturbation-paper.md](../validation/2026-06-28-adversarial-perturbation-paper.md), [2026-06-28-final-claim-audit.md](../validation/2026-06-28-final-claim-audit.md) | State as a synthetic model-internal perturbation measurement of the threat-model boundary. Do not state attacker prevalence, exploitability, or real-world false-positive rate. |
| The 80 percent interval absorbs the CAL8 likelihood band | Public proof harness plus public validation memo | `validation/interval_coverage.py`, `tests/test_interval_coverage.py`, [interval-coverage.md](../validation/interval-coverage.md), [2026-06-28-final-claim-audit.md](../validation/2026-06-28-final-claim-audit.md) | State as model-internal perturbation coverage, not ground-truth frequentist coverage. |
| Posteriors are stable under +/-20 percent likelihood perturbation | Public proof harness plus public validation memo | `validation/likelihood_sensitivity.py`, `tests/test_calibration_metrics.py`, [cal8-likelihood-sensitivity.md](../validation/cal8-likelihood-sensitivity.md), [2026-06-28-final-claim-audit.md](../validation/2026-06-28-final-claim-audit.md) | State as sensitivity to elicited likelihoods, not evidence of real-world calibration. |
| The Bayesian and graph layers add value over simple matching | Public validation memo | `validation/layer_ablation.py`, `tests/test_layer_ablation.py`, [layer-ablation.md](../validation/layer-ablation.md), [2026-06-28-final-claim-audit.md](../validation/2026-06-28-final-claim-audit.md) | State as synthetic layer contribution and MNAR price under the model's own generated worlds. |
| DMARC full posterior agrees strongly with the DMARC record | Aggregate-only private memo | `validation/reference_calibration.py`, [reference-calibration.md](../validation/reference-calibration.md), [2026-06-28-full-corpus-calibration-refresh.md](../validation/2026-06-28-full-corpus-calibration-refresh.md) | State as DMARC-anchored consistency, not clean calibration. |
| DMARC-held-out residual fails as an independent predictor | Aggregate-only private memo | `validation/reference_calibration.py`, [public-list-calibration.md](../validation/public-list-calibration.md), [statistical-assurance.md](statistical-assurance.md) | State as a negative result and keep the residual explanation prominent. |
| DMARC-held-out residual collapse is explainable from the remaining signal strengths | Committed model data plus aggregate-only private memo | `src/recon_tool/data/bayesian_network.yaml`, [2026-06-28-full-corpus-calibration-refresh.md](../validation/2026-06-28-full-corpus-calibration-refresh.md), [statistical-assurance.md](statistical-assurance.md) | State as a diagnostic reading: after DMARC is masked, MTA-STS is too rare and strict SPF is too weak to recover the label. Do not state causal proof. |
| M365 tenancy DNS-only predictor corroborates provider attestation | Aggregate-only private memo | `validation/tenancy_reference_calibration.py`, `tests/test_tenancy_reference_calibration.py`, [public-list-calibration.md](../validation/public-list-calibration.md), [m365-tenancy-decision.md](m365-tenancy-decision.md) | State as channel-split corroboration with shared tenant-provisioning common-cause caveat. Do not state independent calibration. |
| Google Workspace tenancy has only a one-sided check | Aggregate-only private memo | `validation/tenancy_reference_calibration.py`, [public-list-calibration.md](../validation/public-list-calibration.md), [statistical-assurance.md](statistical-assurance.md) | State recall on attested positives only. Do not imply authoritative negatives. |
| Split conformal coverage is measured on labelable nodes | Aggregate-only private memo plus tested pure logic | `validation/conformal_coverage.py`, `tests/test_conformal_coverage.py`, [public-list-calibration.md](../validation/public-list-calibration.md) | State the exchangeability boundary and do not extend it to hardened non-exchangeable targets. |
| ECE estimator uncertainty is separated from model behavior | Invariant plus tested pure logic | `validation/calibration_estimators.py`, `tests/test_calibration_estimators.py`, `tests/test_reference_calibration.py` | State that new calibration summaries include equal-mass, mean-confidence ECE with deterministic bootstrap CI. Do not revise older memo numbers until the corpus runs are rerun. |
| Entropy reduction and posture stratification summarize what the public channel still leaks | Public validation memo | `validation/posture_distributions.py`, `tests/test_posture_distributions.py`, [public-list-calibration.md](../validation/public-list-calibration.md), [public-label-snapshot-decision.md](public-label-snapshot-decision.md) | State as a public-list cross-check across about 575 public domains and 22 disjoint sectors. Keep the sparse-tier hardening interpretation. Treat public-list numbers as robustness checks rather than population rates, benchmark prevalence, or private-corpus population transfer. |
| Per-vertical residual failure generalizes across the curated cohort | Aggregate-only private memo | [2026-06-28-full-corpus-calibration-refresh.md](../validation/2026-06-28-full-corpus-calibration-refresh.md), [statistical-assurance.md](statistical-assurance.md) | State across the 22 disclosed private-corpus verticals only. Do not generalize beyond that curated population. |
| The discussion and conclusion do not claim broad calibration | Aggregate-only private memo plus public claim audit | [2026-06-28-full-corpus-calibration-refresh.md](../validation/2026-06-28-full-corpus-calibration-refresh.md), [m365-tenancy-decision.md](m365-tenancy-decision.md), [2026-06-28-final-claim-audit.md](../validation/2026-06-28-final-claim-audit.md) | State that recon has no clean independent calibration result today; the DMARC residual is a negative result, M365 is corroboration, and Google Workspace is one-sided recall. |
| The public artifact is signed, provenance-linked, and reproducible as a build | Invariant | [supply-chain.md](supply-chain.md), `tests/test_release_workflow_contract.py`, `tests/test_scorecard_posture.py` | State build reproducibility and release provenance. Do not claim independently reproduced empirical results. |
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
8. The public-list sampling boundary must stay linked to
   [public-label-snapshot-decision.md](public-label-snapshot-decision.md):
   public-list numbers are robustness checks rather than population rates.
9. The current final claim audit is recorded in
   [2026-06-28-final-claim-audit.md](../validation/2026-06-28-final-claim-audit.md).
   Rerun it after any experiment, wording, package, or claim-map change.
