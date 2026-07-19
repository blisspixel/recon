# Assurance case

This document is for anyone evaluating recon as a building block they will trust:
piped into automation, handed to an AI agent, fed into a SIEM, or relied on for
vendor diligence. It takes each promise recon makes and maps it to the mechanism
that implements it, the test that proves it, and the residual risk the mechanism
does not cover. The goal is that you can audit the trust claims rather than take
them on faith.

It is deliberately honest about residuals. A passive heuristic tool that names
what it cannot do is more trustworthy than one that overclaims, and the residuals
below are the standing backlog, not hidden caveats. The prose threat model is
[security.md](security.md); the concrete bounds are
[operational-contract.md](operational-contract.md); the release integrity story
is [supply-chain.md](supply-chain.md); the uncertainty model is
[correlation.md](correlation.md).

Every "proven by" reference is a test that exercises the actual code path. Where
a mechanism is real but not yet directly asserted, it is listed in
[Standing gaps](#standing-gaps) rather than claimed as proven. The references in
this document and in the [traceability matrix](traceability-matrix.md) are
machine-checked in CI (`scripts/check_traceability.py`, gated by
`tests/test_traceability.py`): a renamed test or constant fails the build rather
than orphaning a row here.

## Promise 1: Bounded public-metadata collection

**Claim.** Collection is passive in scope. recon sends no credentials, runs no
inbound listener, and performs no active scan. DNS reads use the configured recursive
resolver, so authoritative DNS infrastructure may observe resulting resolver
traffic. The standard MTA-STS policy fetch is the only default target-owned HTTP
or application request. The Google CSE discovery probe and BIMI VMC certificate
fetch are opt-in (`--direct-probes`).

| Mechanism | Proven by | Residual |
|---|---|---|
| `active_probes` gates the CSE probe: `GoogleSource.lookup` makes no call without it | `test_passive_default::test_google_source_passive_by_default_makes_no_cse_probe` | When the operator opts in, the probe is intentionally target-visible (by design) |
| `active_probes` gates the BIMI VMC fetch; presence is still read from DNS | `test_passive_default::test_bimi_vmc_not_fetched_by_default` | Same: opt-in is intentional contact |
| `recon batch --summary` reports only aggregate fields, never the input domains | `test_cohort_summary_cli` (aggregate structure) | The no-domain guarantee holds by construction (the summary never reads the domain keys); the test asserts structure, not a negative domain assertion |

## Promise 2: Bounded and resilient

**Claim.** No single attacker-influenceable input (a DNS record, a CT SAN, an
identity-endpoint body, a poisoned cache file) can crash recon, hang it, or make
it consume unbounded resources. Every boundary degrades to a clean result within
a named cap and timeout.

| Threat | Mechanism | Proven by | Residual |
|---|---|---|---|
| Decompression bomb (gzip body decoding to GBs) | identity `Accept-Encoding` + refuse compressing `Content-Encoding` (`_RefusingStream`); 10 MB raw cap (`_MaxBytesStream`) | `test_resilience_hardening::TestDecompressionBombGuard` | Refusal triggers only on enumerated encodings; a non-standard token would still be size-capped at 10 MB raw |
| Deeply-nested or excessive-numeric JSON in a poisoned cache, limiter snapshot, delta snapshot, client config, or CT payload | cache and limiter readers bind metadata and bounded reads to one regular-file descriptor, reject mutation, cap nesting, and validate schema fields; other local readers catch parser recursion and numeric-limit failures and apply their documented byte caps | `test_json_limits`; `test_resilience_hardening::TestPoisonedCacheDegrades`, `::test_rate_limit_load_persisted_degrades_on_poison`, `::TestCtProviderRecursionError`; `test_delta::TestLoadPrevious`; `test_doctor_client`; `test_cache_roundtrip::TestCacheDiskOperations`; `test_ct_cache::TestCTCachePutGet` | Descriptor identity protection applies to cache and limiter state; other bounded readers remain inside the invoking user's local configuration boundary |
| CT co-occurrence graph blow-up (reused SAN set across many certs) | `_MAX_GRAPH_ENTRIES`, `MAX_GRAPH_NODES`, `_MAX_EDGE_ISSUER_SAMPLES`, per-cert SAN cap | `test_resilience_hardening::TestInfraGraphEntryBound` | none material |
| CT response flood (entries, SANs, bursts, clusters) | `_MAX_CRTSH_ENTRIES`, `_MAX_SANS_PER_CERT`, `_MAX_CRTSH_RAW_NAMES`, `_MAX_CRTSH_CERT_SUMMARY_ENTRIES` (CertSpotter too), `_MAX_PAGES`, burst/cluster caps | `test_hostile_input_bounds::TestCrtshEntryBounds`, `::TestCtGroupingBounds`; `test_cert_providers::TestCertSpotterAggregateBounds`; `test_crtsh.py` | none material |
| ReDoS via a crafted DNS value + catalog/custom/ephemeral regex | structural validator plus input-length caps; session-injected expressions additionally allow at most one repetition operator | `test_security::TestReDoSPrevention`; `test_ephemeral_fingerprints`; `test_hostile_input_bounds::TestDnsParserBounds` | Catalog validation remains heuristic; bounded match inputs are the final backstop for trusted catalog patterns |
| SPF redirect loop / Autodiscover domain flood / XML entity expansion | SPF depth cap 3; `_MAX_AUTODISCOVER_DOMAINS`; defusedxml | `test_hostile_input_bounds::TestDnsParserBounds::test_spf_redirect_loop_terminates`, `::TestAutodiscoverBounds` | none material |
| A hanging or slow source | aggregate `asyncio.wait_for(RESOLVE_TIMEOUT)`; per-query `DNS_QUERY_TIMEOUT`; bounded redirects and cumulative retry sleep; numeric `Retry-After` is accepted only when finite and non-negative, while malformed, date-form, negative, and non-finite values use bounded exponential backoff | `test_source_fault_injection::test_hanging_source_trips_the_aggregate_timeout`; `test_resilience_hardening::TestHttpBounds` (production constants, redirect cap, retry-sleep cap); `test_http_advanced::TestRetryTransport` (header semantics); `test_resilience_hardening::TestDnsBounds` (per-query DNS timeout) | none material |
| Hostile home-directory YAML overlay | profile and motif loaders pre-cap YAML documents at 1 MiB, catch `RecursionError`, validate structure, and skip bad custom files while preserving built-ins | `test_baseline_anomalies::TestProfileSchemaExtension`; `test_motifs::TestUserConfigAdditive` | none material for these loaders |
| Every boundary x failure-mode (malformed / oversized / wrong-shape / 404 / 500 / timeout / network error / empty) | each HTTP identity source returns a clean `SourceResult`, never raises | `test_hostile_input_bounds::TestSourceFaultMatrix` (the explicit matrix) | none material for the HTTP sources |
| Parser and serializer coverage-guided fuzzing | ClusterFuzzLite builds and runs `fuzz/recon_input_fuzzer.py` on pull requests, covering local domain normalization, control-byte stripping, cache deserialization, and formatter serialization without network calls | `tests/test_clusterfuzzlite_integration.py` (config and seed harness); `.github/workflows/clusterfuzzlite.yml` (remote run) | Local tests assert the harness shape and seeds; the coverage-guided search runs only in GitHub Actions |

## Promise 3: Output is safe to render

**Claim.** Attacker-influenceable strings (CT issuer/SAN names, identity fields,
an echoed bad domain) cannot inject terminal escapes,
Rich markup, or markdown structure into the panel, JSON, markdown, or MCP output.

| Mechanism | Proven by | Residual |
|---|---|---|
| `strip_control_chars` (deal-postcondition-pinned) removes C0/DEL/C1 bytes and Unicode bidirectional formatting controls, then caps length, at every source-derived free-text sink | `test_validator::TestStripControlChars`; `test_cert_providers::TestCertDataSanitization`; `test_infra_graph::TestSanAndIssuerSanitization`; `test_ingestion_sanitization` | Printable residue survives by design: a self-logged issuer can still show misleading printable text |
| `is_safe_dns_name` charset-drops any CT SAN outside `[a-z0-9-._*]` | `test_cert_providers::TestCertDataSanitization`; `test_validator::TestIsSafeDnsName` | A non-DNS-but-printable label is dropped wholesale, not partially shown |
| `escape(strip_control_chars(...))` on error/warning sinks; `_markdown_escape` on markdown | `test_security::TestRenderErrorSanitization`, `::TestOutputInjectionSweep`; `test_formatter::TestMarkdownEscaping` | none material for these paths |
| MCP returns observed DNS/CT strings marked as untrusted data, not instructions | `test_data_not_instructions` | Advisory only: the demarcation instructs the consuming agent but cannot force a downstream model to comply |

## Promise 4: Safe to point at an untrusted target

**Claim.** Running recon against a domain whose DNS an attacker controls does not
turn it into an SSRF vector or an internal-DNS oracle.

| Threat | Mechanism | Proven by | Residual |
|---|---|---|---|
| SSRF to a missing-host, non-global, unresolved, or special-use destination (including redirects) | `_SSRFSafeTransport` validates every hop against the public-unicast policy and fails closed on missing hosts, DNS errors, empty answers, and invalid addresses before transport | `test_http::TestSSRFProtection`, `test_http_advanced::TestIsPrivateIpAsync`, `test_http_advanced::TestSSRFSafeTransport` | The validated address is not pinned to the connection, so the documented DNS rebinding TOCTOU residual remains |
| SSRF via an attacker-authored BIMI `a=` URL | `_bimi_vmc_url_is_safe` (https, public host, no IP literal, no creds, default port, no redirects) | `test_bimi_vmc::test_refuses_unsafe_a_url` | Host check is suffix/charset-based, not a live public-suffix lookup |
| Internal-DNS leak: attacker CNAME / SPF redirect to an internal name | per-hop `_is_public_dns_name` denylist; CNAME-only walk (no recursive A/AAAA chase); canonical-name guard in `_safe_resolve` | `test_cname_chain_validation` (entry-point, no-A/AAAA-during-walk, canonical guard, SPF/redirect filters) | Documented tradeoff: split-horizon termini are not dropped; one blind query in the type-dependent-answer case still leaves the resolver (see `security-audit-resolutions.md`) |
| Path traversal, cross-key substitution, or symlink access via a crafted cache key | result and CT paths validate literal host keys inside one resolved parent; payloads are domain-bound; reads reject symlinks and path/descriptor identity changes; writes use random `mkstemp` (`O_CREAT|O_EXCL`) names plus atomic replacement | `test_json_limits`; `test_cache_roundtrip::TestCacheDiskOperations`; `test_ct_cache::TestCTCachePutGet`; `test_cache_cli` | A local actor with permission to replace the cache directory itself already controls the invoking user's configuration boundary |

## Promise 5: Honest about uncertainty

**Claim.** recon reports what the public channel can defensibly reveal, with
provenance, model-relative diagnostics, and explicit limits.

| Mechanism | Where | Residual (the load-bearing honesty) |
|---|---|---|
| The evidence-responsive uncertainty band is computed deterministically from the model posterior and hand-set display mass; `sparse=true` marks the mass floor | [correlation.md](correlation.md); Bayesian interval, fuzz, and topology suites | The band is not a Bayesian credible interval, confidence interval, identification region, or empirical coverage statement. Its width is not generally monotone when evidence changes the mean as well as the mass |
| Under selected plus-or-minus 20 percent likelihood scenarios, the current band contains the perturbed model conditional on every node in the recorded harness | `validation/interval_coverage.py`; gated by `tests/test_interval_coverage.py`; memo in `validation/interval-coverage.md` | A finite model-internal sensitivity experiment, not a bound over all misspecification and not ground-truth calibration. Priors, CPT rows, dependence, and missingness are outside that perturbation set |
| Under fixed local positive-factor assumptions, deleting fired evidence cannot raise local presence odds; the harness checks binding subsets under sampled external contexts | `validation/adversarial_properties.py`; gated by `tests/test_adversarial_properties.py`; formal limits in [correlation.md](correlation.md#34-evidence-removal) | Does not guarantee movement toward 0.5, wider bands, global DAG monotonicity, or robustness to planted evidence. The proposed removal-and-planting envelope remains research |
| The email-policy score agrees with the DMARC record it substantially consumes: historical fixed-bin ECE 0.0761 and historical legacy index-sliced equal-mass ECE 0.0651 over n=2,906 DMARC publishers across 22 development strata | `validation/reference_calibration.py`; aggregate memos; dossier `statistical-assurance.md` | In-sample, publisher-conditional, largely definitional corroboration. With `dmarc_policy` masked, the input-disjoint residual still reuses parameter-development data and performs poorly: historical fixed-bin ECE 0.3747 and historical legacy equal-mass ECE 0.3263. No current tie-preserving numeric estimate exists. Historical iid row-bootstrap ranges carry no coverage claim, and no clean calibration claim remains |
| The 2.2 diagnostics report exactly what the engine computes: each `unit_counterfactuals` entry is a leave-one-unit-out re-inference, per-node signed marginal entropy changes sum to the stored result total, and `partition_stability` is seed-sweep ARI | `tests/test_evidence_semantics_diagnostics.py`; `tests/test_bayesian_masked_units.py` | Counterfactuals are model evidence counterfactuals, never causal claims; deltas are not additive; marginal entropy sums can double count dependent nodes; seed stability is not data stability |
| The first internal claim contract binds the policy scalar to retained raw DMARC evidence, preserves independent positive and explicit-disconfirming `p=reject` certificates, recomputes acyclic monotone closure after canonical ledger union, excludes stale or unavailable units, and fails closed at declared exact bounds | `recon_tool.claim_contract`; `tests/test_claim_contract.py`; `tests/test_cohort_summary_cli.py`; [claim-contracts.md](claim-contracts.md) | Internal dossier only. Opt-in cohort schema 2.2 consumes transient state and raw-bound effective-policy projections. Whole-resolution completion approximates observation time; empty and invalid DNS observations remain unresolved because resolver identity, authority sections, and DNSSEC denial validation are not retained; no public dossier or general claim registry exists |
| Detections are heuristic, rule-based, and solo-maintained, each carrying a vendor-doc reference for re-verification | `data/fingerprints/*`, `fingerprints.md` | Confident-looking output can still be wrong; treat results as indicators for investigation, not facts |
| Accurate attribution guards: label-aware `cname_target` match, shared hostname suffix matching, IDNA round-trip check | `test_security::test_cname_target_match_is_label_aware`, `test_validator::TestHostHasSuffix`, `test_google_identity::TestIsFederatedRedirect`, `test_dns_subdetectors::TestExchangeDkimSuffixMatch`, `test_security::test_idna_lossy_mapping_rejected` | Dot-less infra markers keep substring semantics by design; a registered homoglyph apex is out of scope |

## Promise 6: The artifact is verifiable

**Claim.** A published release traces back to the exact source and workflow that
produced it, and PyPI plus GitHub serve the same sealed wheel and sdist bytes.
Consumers can verify the signed evidence and compare a local rebuild under a
matched environment. Full details and the bounded recipe are in
[supply-chain.md](supply-chain.md).

| Mechanism | Proven by |
|---|---|
| Exact uv and a hash-locked Hatchling dependency graph constrain every release-shaped build; the committed constraints are a frozen PEP 735 build-group export and ship in the sdist | `test_build_constraints::test_build_root_and_uv_are_exactly_selected`; `test_build_constraints::test_build_constraints_are_exact_complete_and_hashed`; `test_build_constraints::test_build_constraints_match_frozen_build_group`; `test_build_constraints::test_artifact_workflows_select_required_uv_version`; `test_package_invariants::test_sdist_retains_public_sources_and_excludes_private_artifacts` |
| Same-job deterministic-build check (`SOURCE_DATE_EPOCH`) creates the sdist, reconstructs its wheel, repeats the sequence, and matches both hashes | `ci.yml` `reproducible-build` job; `test_check_script::test_reproducible_build_smokes_built_wheel_entry_points` |
| A sealed release must contain exactly one tag-matching wheel and sdist; the wheel executes through both installed entry points in a separate read-only job before either publication channel can run | `release.yml` `package-smoke` job; `test_release_workflow_contract::TestPackageSmokeJob` |
| PyPI must expose exactly the sealed wheel and sdist from bounded, version-scoped metadata with trusted file URLs and matching SHA-256 digests before GitHub Release publication; remote readiness reuses that trust boundary, repeats parity, and names both shared digests | `test_release_channel_parity::test_public_metadata_validator_returns_only_the_exact_safe_pair`; `test_release_channel_parity::test_exact_pair_returns_shared_digests`; `test_release_workflow_contract::TestPublishedChannelParity`; `test_release_readiness::test_release_channel_parity_reports_exact_digest_evidence` |
| A remote readiness report cannot combine current-main CI with an older or moved published package: the remote and local current project-version tag plus `HEAD` must resolve to the same full commit | `release_readiness::_check_release_tag_binding`; `test_release_readiness::test_remote_release_tag_binding_rejects_mixed_head_and_release_state`; `test_release_readiness::test_remote_release_tag_binding_rejects_moved_public_tag` |
| Local release transaction starts from clean current `main`, synchronizes exact-version installer helpers with other owned surfaces, stages only those surfaces, creates one reviewed tag, and restores files, index, commit, and owned tag when the mutation transaction fails | `test_release_script::test_release_surface_generation_updates_installers_and_artifacts`, `test_release_script::test_release_transaction_owns_both_installer_helpers`, `test_release_script::test_release_push_command_names_only_the_reviewed_tag`, `test_release_script::test_release_rollback_restores_files_index_commit_and_owned_tag`, `test_install_scripts::test_installers_bind_the_reviewed_release_version_and_owner` |
| A release tag must match the project version and dated nonempty changelog section, identify the workflow SHA, and be contained in freshly fetched current `main` before the test gate can run | `test_validate_release_tag::test_matching_tag_with_notes_and_main_ancestry_passes`, `test_validate_release_tag::test_mismatched_tag_fails_before_git`, `test_validate_release_tag::test_non_main_tag_fails`, `test_release_workflow::test_release_preflight_blocks_mismatched_or_non_main_tags` |
| CycloneDX generation rejects every nonzero audit status; output contains the exact versioned project root and complete dependency edge; publication and remote verification fail rather than repairing malformed or non-UTF-8 completed evidence | `test_run_dependency_audit::test_enforcing_workflows_use_bounded_audit_runner`, `test_release_workflow_contract::TestSbomJobIsIsolated::test_sbom_job_validates_complete_project_bom`, `test_finalize_sbom::test_finalize_sbom_adds_project_root_and_dependency_edge`, `test_finalize_sbom::test_completed_sbom_validation_fails_without_repair`, `test_finalize_sbom::test_completed_sbom_validation_rejects_non_utf8_bytes`, `test_release_workflow::test_pypi_publication_waits_for_valid_sbom` |
| GitHub verification for releases produced by the current workflow binds the wheel, sdist, and completed SBOM to the exported bundle, exact release workflow, source tag, commit digest, and hosted-runner boundary. The exact v2.6.3 historical exception requires wheel and sdist provenance plus completed SBOM structure validation; PyPI uses pinned PEP 740 verification and OIDC Trusted Publishing | `test_release_readiness::test_github_attestations_verify_wheel_sdist_and_sbom`; `test_release_readiness::test_github_attestations_preserve_exact_v263_legacy_subject_boundary`; `release.yml` (`attest`, `publish-pypi` jobs); `test_release_workflow_contract::TestAttestationJob` |
| Existing GitHub Release recovery permits asset replacement only for the exact published tag and title with mutable, expected-only inventory, complete or partial; draft, prerelease, immutable, duplicate, unexpected, and malformed state fails before `--clobber`, and the remote tag must still resolve to the workflow SHA | `check_release_recovery::validate_release_recovery`; `test_release_recovery::test_unsafe_existing_release_state_is_rejected`; `test_release_workflow_contract::TestGithubReleaseAttachesBothArtifacts` |

Residual: the uv and build-backend graph are fixed, but Python, the Ubuntu
runner image, operating-system libraries, and archive environment are not fully
content-addressed for universal cross-environment byte identity. Full SLSA
Level 3 provenance via the reusable generator workflow stays deferred as
disproportionate for a passive single-maintainer tool.

## Standing gaps

No standing proving-test gaps are currently tracked in this document. The
2026-06 proving backlog that previously lived here is now closed:

- Production HTTP and resolver bounds are pinned by
  `test_resilience_hardening::TestHttpBounds`.
- The per-query DNS timeout is asserted in isolation by
  `test_resilience_hardening::TestDnsBounds`.
- Profile and motif home-directory YAML overlays have dedicated hostile-input
  coverage in `test_baseline_anomalies::TestProfileSchemaExtension` and
  `test_motifs::TestUserConfigAdditive`.

New residuals should be added here when a mechanism is present in code but not
yet directly asserted by a test.
