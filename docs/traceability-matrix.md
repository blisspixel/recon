# Traceability matrix

Every promise recon makes should map to the test that keeps it. The
[assurance case](assurance-case.md) does that for the security promises
(threat, mechanism, proving test, residual); this matrix covers the layer
above it: the box invariants the roadmap commits to, the operational
contract's load-bearing bounds, the output contract, and the inference
trust chain.

**This document is machine-checked.** `scripts/check_traceability.py`
parses every backticked reference here and in the assurance case and
verifies, via the AST, that the referenced test, function, class,
constant, or file still exists; `tests/test_traceability.py` runs that
check in CI. A renamed test breaks the build, not just the doc. Rows
whose proof is structural rather than test-shaped say so explicitly:
an honest "no direct test" is a row a future patch can close, not a
hidden gap.

## The box invariants

The eight invariants from the [roadmap](roadmap.md#invariants). Anything
new must fit inside this box.

| Invariant | Mechanism | Proven by | Residual / notes |
|---|---|---|---|
| Public metadata only; MTA-STS is the only default target-owned HTTP/application request, and Google CSE / BIMI certificate requests are opt-in | Default lookups use the configured recursive DNS resolver, read CT logs and unauthenticated provider identity endpoints, and fetch MTA-STS only when published; `active_probes` gates CSE and BIMI requests | `test_gws_features::TestFetchMtaStsPolicy::test_mta_sts_enforce_mode`, `test_gws_features::TestFetchMtaStsPolicy::test_no_policy_fetch_without_mta_sts_record`, `test_passive_default::test_google_source_passive_by_default_makes_no_cse_probe`, `test_passive_default::test_bimi_vmc_not_fetched_by_default` | Authoritative DNS may observe resolver traffic; MTA-STS is intentional default contact; opted-in probes are intentional direct contact |
| No credentials, API keys, paid feeds, port scanning, exploit checks, or target application crawling | No auth configuration or scanner surface exists; runtime dependencies carry no paid-provider SDK; ordinary HTTP collectors are fixed public-metadata endpoints | `scripts/check_cost_surface.py` checks runtime code, wheel packages, dependencies, and workflows; `tests/test_cost_surface.py` and `tests/test_passive_default.py` pin the structural and default-contact boundaries | The cost guard is marker-based; new provider vocabulary must be added when the ecosystem changes |
| No runtime aggregate database and no committed or published real-target corpus or per-domain rows | Packaged data is limited to reviewed catalogs and schema assets; cohort reduction is compute-and-forget; validation hygiene rejects private run paths, root per-domain dumps, and target-domain fields | `tests/test_package_invariants.py`, `tests/test_validation_hygiene.py` | Maintainer-local ignored data remains outside Git; the package test proves contents, not deletion of an operator's external files |
| Public examples are fictional, synthetic, reserved, or aggregate-only | Validation hygiene admits reserved and fictional examples and rejects non-fictional command examples and corpus lines; public fixtures use the reserved Contoso/Fabrikam/Northwind set | `test_validation_hygiene::test_recon_example_with_real_domain_fails`, `test_validation_hygiene::test_validation_corpus_lines_must_be_fictional_or_reserved`, `test_validation_hygiene::test_synthetic_and_fictional_validation_artifacts_pass` | The automated semantic scan is strongest in validation artifacts; general prose remains review-held |
| Observations are hedged and provenance-bearing; sparse or degraded evidence lowers confidence or remains unresolved | Collection views mask unavailable channels, confidence is distinct-source and same-claim scoped, explanation output reports disconnected terminals, and generated exposure copy uses neutral templates | `tests/test_collection_view.py`, `tests/test_bayesian_collection_missingness.py`, `tests/test_explanation_coverage.py`, `test_exposure::TestProperty8NeutralGeneratedCopy` | `provenance_complete` proves reachability in the reconstructed graph, not exact generation-time lineage for every reconstructed insight or posture association |
| Stable CLI, JSON, MCP, cache, and import surfaces change only through compatibility discipline | Required JSON fields are code-owned and generated into both schema copies; batch shapes, cache cross-version reads, and public imports have compatibility tests | `tests/test_json_schema_contract.py`, `tests/test_batch_ndjson_schema.py`, `tests/test_cache_cross_version_compatibility.py`, `tests/test_backward_compat.py` | Additive 2.x fields still require accurate documentation; behavior outside the named stable surfaces can evolve |
| Network, parser, cache, schema, and output behavior is bounded | Named limits cap time, response bodies, redirects, retries, DNS match inputs, CT retention, cache payloads, schema depth, and rendered collections; the operational bounds below enumerate the load-bearing subset | `tests/test_hostile_input_bounds.py`, `tests/test_resilience_hardening.py`, `tests/test_adversarial_render.py`, `tests/test_batch_ndjson_schema.py` | Bounds limit local cost and output volume; upstream latency and availability remain external |
| Root, documentation, source, logs, and agent working files follow the canonical directory layout | Root-anchored ignore rules isolate `.agent/`, `logs/`, and tool artifacts; the package uses `src/`; nested agent state and root package shadows are rejected | `tests/test_repository_hygiene.py`, `tests/test_source_hygiene.py` | Ignored local tool caches can exist in the working tree without becoming project structure |

## Operational contract bounds

The load-bearing rows of [operational-contract.md](operational-contract.md):
the constant that implements each bound and the test that pins the
behavior. The full threat-by-threat version is assurance-case Promise 2.

| Bound | Constant | Proven by |
|---|---|---|
| Aggregate resolve wall-clock | `src/recon_tool/resolver.py::RESOLVE_TIMEOUT` | `test_source_fault_injection::test_hanging_source_trips_the_aggregate_timeout` |
| Per-query DNS timeout | `src/recon_tool/sources/dns_base.py::DNS_QUERY_TIMEOUT` | `test_resilience_hardening::TestDnsBounds` |
| HTTP response body cap + decompression-bomb refusal | `src/recon_tool/http.py::_MAX_RESPONSE_BYTES` | `test_resilience_hardening::TestDecompressionBombGuard`, `test_resilience_hardening::TestHttpBounds` |
| Redirect and cumulative retry-sleep caps | `src/recon_tool/http.py::MAX_REDIRECTS`, `src/recon_tool/http.py::_MAX_TOTAL_RETRY_SLEEP` | `test_resilience_hardening::TestHttpBounds` |
| `Retry-After` accepts only finite non-negative numeric delays, clamps each delay, and otherwise falls back to exponential backoff | `src/recon_tool/http.py::_MAX_TOTAL_RETRY_SLEEP` | `test_http_advanced::TestRetryTransport` |
| TenantInfo and CT cache readers reject wrong-shaped or numerically invalid data while current round trips preserve certificate and infrastructure extensions | `src/recon_tool/cache.py::tenant_info_from_dict`, `src/recon_tool/ct_cache.py::ct_cache_get` | `test_cache_roundtrip::TestCacheDiskOperations`, `test_ct_cache::TestCTCachePutGet` |
| DNS regex-match input caps (TXT / CNAME / subdomain-TXT) | `src/recon_tool/fingerprints.py::_MAX_TXT_MATCH_LENGTH` and siblings | `test_hostile_input_bounds::TestDnsParserBounds` |
| CT entry / SAN / page floods | `src/recon_tool/sources/cert_providers.py::_MAX_CRTSH_ENTRIES` and siblings | `test_hostile_input_bounds::TestCrtshEntryBounds`, `test_hostile_input_bounds::TestCtGroupingBounds` |
| Every HTTP identity source x failure mode degrades to a clean result | per-source guards; clean `SourceResult` on every failure | `test_hostile_input_bounds::TestSourceFaultMatrix` |
| PR-scoped coverage-guided parser fuzzing | `.github/workflows/clusterfuzzlite.yml`, `.clusterfuzzlite/project.yaml`, `fuzz/recon_input_fuzzer.py` | `tests/test_clusterfuzzlite_integration.py` |
| Hash-pinned ClusterFuzzLite runtime requirements stay synced to `uv.lock` | `.clusterfuzzlite/requirements.txt`, `scripts/check_clusterfuzzlite_requirements.py` | `tests/test_clusterfuzzlite_requirements_check.py` |

## The output contract

| Promise | Mechanism | Proven by |
|---|---|---|
| `--json` output validates against the locked v2.0 schema; schema and emitter cannot drift apart | `docs/recon-schema.json` is the contract; the test regenerates real output and validates it | `tests/test_json_schema_file.py` |
| Batch / NDJSON records keep the documented shapes (`record_type`, `error_kind`, the always-wrapper) | the SH1-SH9 schema-hardening shapes | `tests/test_batch_ndjson_schema.py` |
| Stable exit codes (0 / 1 / 2 / 3 / 4) a script can branch on | `src/recon_tool/exit_codes.py::EXIT_SUCCESS`, `src/recon_tool/exit_codes.py::EXIT_NO_DATA` and siblings | `tests/test_exit_codes.py` |

## The inference trust chain

The layered argument that the Bayesian numbers can be trusted, each
layer with its own gate:

| Layer | Claim | Standing artifact | Gate |
|---|---|---|---|
| Correctness | Variable elimination matches an independent 512-state latent-joint reference over the structured none/one/all evidence sweep and exhaustive local subsets for three factor-heavy nodes | `validation/differential_verification.py` | `tests/test_bayesian_differential.py` |
| Change control | A CPT edit that shifts an implied marginal beyond the band must be acknowledged in the diff | `validation/drift_check.py`, `validation/inference_baseline.json` | `tests/test_drift_check.py` |
| Uncertainty honesty | The 80% band contains selected perturbed-model conditionals in the finite, seeded CAL8 scenario; this is not a general imprecision bound | `validation/interval_coverage.py`, memo `interval-coverage.md` | `tests/test_interval_coverage.py` |
| Test strength | Round 6 kills 91.35% of tested mutants (655 killed, 62 survivors of 717), with an 88% floor | `mutation.toml`, memo `mutation-gate.md` | `mutation.yml` (blocking when the mutated surface or kill set changes; weekly) |
| Evidence semantics | Group reduction and declarative absence behave as implemented | [correlation.md](correlation.md) sections 3.2 and 3.3 | `tests/test_bayesian_evidence_groups.py` |
| Adversarial property (removal only) | Under the proposition's fixed local positive-factor assumptions, deleting a fired unit cannot raise local presence odds; no claim is made about movement toward 0.5, band width, or evidence planting | [correlation.md](correlation.md) section 3.4; `validation/adversarial_properties.py` | `tests/test_adversarial_properties.py` |

## Release integrity

Covered in [supply-chain.md](supply-chain.md) and assurance-case
Promise 6; listed here for completeness of the requirement-to-gate map.

| Requirement | Gate |
|---|---|
| Local release starts from clean current `main`, updates only owned surfaces, rolls back a failed mutation transaction, and pushes `main` plus the reviewed tag atomically | `scripts/release.py`; `test_release_script::test_release_push_command_names_only_the_reviewed_tag`, `test_release_script::test_release_rollback_restores_files_index_commit_and_owned_tag` |
| Tag, project version, dated nonempty changelog section, tagged SHA, and current `main` ancestry agree before release tests run | `scripts/validate_release_tag.py`; `test_validate_release_tag::test_matching_tag_with_notes_and_main_ancestry_passes`, `test_validate_release_tag::test_non_main_tag_fails`, `test_release_workflow::test_release_preflight_blocks_mismatched_or_non_main_tags` |
| Artifact builds select exact uv and a hash-locked build group whose frozen export is committed and shipped in the sdist | `build-constraints.txt`; `test_build_constraints::test_build_root_and_uv_are_exactly_selected`; `test_build_constraints::test_build_constraints_match_frozen_build_group`; `test_package_invariants::test_sdist_retains_canonical_fingerprint_sources_and_generated_artifact` |
| Same source and fixed epoch produce matching sdist and reconstructed-wheel artifacts across two constrained builds in one CI job | `ci.yml` reproducible-build job; `test_check_script::test_reproducible_build_smokes_built_wheel_entry_points` |
| The sealed release contains exactly one tag-matching wheel and sdist, and the wheel executes through both installed entry points before PyPI or GitHub publication | `release.yml` package-smoke job; `test_release_workflow_contract::TestPackageSmokeJob` |
| CycloneDX output has the project root and dependency edge, and SBOM failure blocks PyPI and GitHub publication | `scripts/finalize_sbom.py`; `test_finalize_sbom::test_finalize_sbom_adds_project_root_and_dependency_edge`, `test_finalize_sbom::test_finalize_sbom_rejects_incomplete_payloads`, `test_release_workflow::test_pypi_publication_waits_for_valid_sbom`, `test_release_workflow_contract::TestGithubReleaseAttachesBothArtifacts` |
| Signed, attested, traceable releases use GitHub provenance and PyPI Trusted Publishing | `release.yml` (attestations and trusted publishing), `tests/test_release_workflow_contract.py` |

## How this document stays true

`tests/test_traceability.py` runs `scripts/check_traceability.py` over
this file and the assurance case on every CI run. The checker resolves
each backticked reference (test node, source constant, file) against
the AST of the current tree and fails on anything that no longer
exists. What it cannot catch: a test that still exists but no longer
asserts what the row claims. That residual is the same one every
traceability scheme carries; the mitigation is that rows reference
specific, narrowly-scoped tests rather than broad suites where
possible.
