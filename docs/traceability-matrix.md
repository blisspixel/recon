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

The six invariants from the [roadmap](roadmap.md#invariants). Anything
new must fit inside this box.

| Invariant | Mechanism | Proven by | Residual / notes |
|---|---|---|---|
| Passive only: no active scanning, port probes, zone transfers, or target TLS handshakes; direct probes are opt-in | `active_probes` gates the Google CSE probe and the BIMI VMC fetch; default lookups read DNS, CT logs, and the providers' identity endpoints only | `test_passive_default::test_google_source_passive_by_default_makes_no_cse_probe`, `test_passive_default::test_bimi_vmc_not_fetched_by_default`, `test_passive_default::test_resolve_tenant_passive_by_default` | The MTA-STS policy fetch is the one default request the target's own servers see (documented in the README); opted-in probes are intentional contact |
| Zero credentials, zero API keys, zero paid APIs | No auth configuration surface exists; every source is an unauthenticated public endpoint; the runtime dependency set in `pyproject.toml` carries no vendor SDK | No direct test (structural): there is no credential code path to exercise. Reviewed at each dependency change; `ci.yml` audits the locked dependency surface | A future source addition could regress this; the invariant is enforced by review, not by a gate |
| No bundled ML models, embeddings, ASN data, GeoIP data, or local aggregate intelligence database | Packaged data is the fingerprint catalog and the Bayesian network YAML only; the cohort summary is compute-and-forget (no persistent store) | No direct test (structural): the wheel contents are inspectable, and the `ci.yml` reproducible-build job makes the artifact verifiable bit-for-bit | The dependency floor (no numpy/scipy/pandas in core) is visible in `pyproject.toml`; a packaging test pinning wheel contents is a candidate follow-up |
| No user-code plugin system: custom fingerprints, signals, profiles, and motifs are data files only | Home-directory overlays are parsed with `yaml.safe_load`, validated structurally, and are additive (cannot override built-ins) | `test_custom_signals::test_custom_signals_are_additive`, `test_motifs::TestUserConfigAdditive` | The overlay loaders lack a dedicated hostile-YAML suite (named in the assurance case's standing gaps) |
| Hedged output: sparse evidence stays qualified, dense evidence never absolute | The 80% credible interval with `_MIN_N_EFF` floor (`recon_tool/bayesian.py::_credible_interval`), the `sparse` flag, and the CAL14 declarative-absence model | `test_node_stability_criteria` (per-node stability criteria), `tests/test_interval_coverage.py` (interval width absorbs the elicitation band), `tests/test_bayesian_evidence_groups.py` (CAL7/CAL14 semantics) | Evidence-responsive, not ground-truth calibrated; the wording discipline is CAL13 |
| Neutral language: observable facts only, no offensive guidance or maturity verdicts | Generated copy is assembled from neutral templates | `test_exposure::TestProperty8NeutralGeneratedCopy` walks every string field of the exposure assessment | Covers the exposure surface; panel and insight copy is held by review and the golden renders, not a wording test |

## Operational contract bounds

The load-bearing rows of [operational-contract.md](operational-contract.md):
the constant that implements each bound and the test that pins the
behavior. The full threat-by-threat version is assurance-case Promise 2.

| Bound | Constant | Proven by |
|---|---|---|
| Aggregate resolve wall-clock | `recon_tool/resolver.py::RESOLVE_TIMEOUT` | `test_source_fault_injection::test_hanging_source_trips_the_aggregate_timeout` |
| HTTP response body cap + decompression-bomb refusal | `recon_tool/http.py::_MAX_RESPONSE_BYTES` | `test_resilience_hardening::TestDecompressionBombGuard`, `test_resilience_hardening::TestHttpBounds` |
| Redirect and cumulative retry-sleep caps | `recon_tool/http.py::MAX_REDIRECTS`, `recon_tool/http.py::_MAX_TOTAL_RETRY_SLEEP` | `test_resilience_hardening::TestHttpBounds` |
| DNS regex-match input caps (TXT / CNAME / subdomain-TXT) | `recon_tool/fingerprints.py::_MAX_TXT_MATCH_LENGTH` and siblings | `test_hostile_input_bounds::TestDnsParserBounds` |
| CT entry / SAN / page floods | `recon_tool/sources/cert_providers.py::_MAX_CRTSH_ENTRIES` and siblings | `test_hostile_input_bounds::TestCrtshEntryBounds`, `test_hostile_input_bounds::TestCtGroupingBounds` |
| Every HTTP identity source x failure mode degrades to a clean result | per-source guards; clean `SourceResult` on every failure | `test_hostile_input_bounds::TestSourceFaultMatrix` |

## The output contract

| Promise | Mechanism | Proven by |
|---|---|---|
| `--json` output validates against the locked v2.0 schema; schema and emitter cannot drift apart | `docs/recon-schema.json` is the contract; the test regenerates real output and validates it | `tests/test_json_schema_file.py` |
| Batch / NDJSON records keep the documented shapes (`record_type`, `error_kind`, the always-wrapper) | the SH1-SH9 schema-hardening shapes | `tests/test_batch_ndjson_schema.py` |
| Stable exit codes (0 / 1 / 2 / 3 / 4) a script can branch on | `recon_tool/exit_codes.py::EXIT_SUCCESS`, `recon_tool/exit_codes.py::EXIT_NO_DATA` and siblings | `tests/test_exit_codes.py` |

## The inference trust chain

The layered argument that the Bayesian numbers can be trusted, each
layer with its own gate:

| Layer | Claim | Standing artifact | Gate |
|---|---|---|---|
| Correctness | Variable elimination matches an independent full-joint reference on every enumerable evidence configuration | `validation/differential_verification.py` | `tests/test_bayesian_differential.py` |
| Change control | A CPT edit that shifts an implied marginal beyond the band must be acknowledged in the diff | `validation/drift_check.py`, `validation/inference_baseline.json` | `tests/test_drift_check.py` |
| Uncertainty honesty | The 80% interval absorbs the acknowledged elicitation imprecision (CAL8 band) | `validation/interval_coverage.py`, memo `interval-coverage.md` | `tests/test_interval_coverage.py` |
| Test strength | The suite notices subtle defects: 91.4% mutation kill over tested mutants (123 survivors of 1,431, residual classified equivalent), floor at 88% | `mutation.toml`, memo `mutation-gate.md` | `mutation.yml` (blocking on the mutated surface; weekly) |
| Evidence semantics | CAL7 group reduction and CAL14 declarative absence behave as documented | [correlation.md](correlation.md) section 4.3 | `tests/test_bayesian_evidence_groups.py` |
| Adversarial robustness (removal only) | Hiding any observed evidence moves a node's presence posterior monotonically toward its all-absent baseline, never to a confident false positive (the suppression-monotonicity proposition; it bounds evidence removal, not the addition of decoy records, [correlation.md](correlation.md) section 4.3) | `validation/adversarial_properties.py` | `tests/test_adversarial_properties.py` |

## Release integrity

Covered in [supply-chain.md](supply-chain.md) and assurance-case
Promise 6; listed here for completeness of the requirement-to-gate map.

| Requirement | Gate |
|---|---|
| Same source, byte-identical artifacts | `ci.yml` reproducible-build job |
| Signed, attested, traceable releases | `release.yml` (attestations, SBOM, trusted publishing), `tests/test_release_workflow_contract.py` |

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
