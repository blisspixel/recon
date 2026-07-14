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
| SSRF to a non-global or special-use IP (incl. via redirect) | `_SSRFSafeTransport` validates every hop's resolved IP against the public-unicast policy | `test_http_advanced::TestSSRFSafeTransport` | DNS rebinding with sub-second TTL is not fully defeated (TOCTOU, documented in `http.py`) |
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
produced it. Consumers can verify the signed provenance and compare a local
rebuild under a matched environment. Full details and the bounded recipe are in
[supply-chain.md](supply-chain.md).

| Mechanism | Proven by |
|---|---|
| Same-job deterministic-build check (`SOURCE_DATE_EPOCH`), matching wheel and sdist hashes under one resolved toolchain | `ci.yml` `reproducible-build` job (builds twice, compares hashes) |
| Local release transaction starts from clean current `main`, stages only owned surfaces, creates one reviewed tag, and restores files, index, commit, and owned tag when the mutation transaction fails | `test_release_script::test_release_push_command_names_only_the_reviewed_tag`, `test_release_script::test_release_rollback_restores_files_index_commit_and_owned_tag` |
| A release tag must match the project version and dated nonempty changelog section, identify the workflow SHA, and be contained in freshly fetched current `main` before the test gate can run | `test_validate_release_tag::test_matching_tag_with_notes_and_main_ancestry_passes`, `test_validate_release_tag::test_mismatched_tag_fails_before_git`, `test_validate_release_tag::test_non_main_tag_fails`, `test_release_workflow::test_release_preflight_blocks_mismatched_or_non_main_tags` |
| CycloneDX output contains the versioned project root and dependency edge, and both publication channels depend on a valid SBOM | `test_finalize_sbom::test_finalize_sbom_adds_project_root_and_dependency_edge`, `test_finalize_sbom::test_finalize_sbom_rejects_incomplete_payloads`, `test_release_workflow::test_pypi_publication_waits_for_valid_sbom`, `test_release_workflow_contract::TestGithubReleaseAttachesBothArtifacts` |
| Sigstore-signed PyPI attestations (PEP 740), GitHub build provenance, and OIDC Trusted Publishing | `release.yml` (`attest`, `publish-pypi` jobs); `tests/test_release_workflow_contract.py` |

Residual: the build backend and runner environment are not fully frozen for
cross-environment byte identity. Full SLSA Level 3 provenance via the reusable
generator workflow stays deferred as disproportionate for a passive
single-maintainer tool.

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
