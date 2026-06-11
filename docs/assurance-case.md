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

## Promise 1: Passive by default

**Claim.** Collection is passive. recon sends no credentials, runs no inbound
listener, and the only requests the queried domain's own servers see by default
is the standard MTA-STS policy fetch. The Google CSE discovery probe and the
BIMI VMC certificate fetch are opt-in (`--direct-probes`).

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
| Deeply-nested JSON in a poisoned cache / CT payload (`RecursionError`) | cache/ct-cache/rate-limit loaders catch `RecursionError` + a 5 MB pre-read size cap; CT providers catch it too | `test_resilience_hardening::TestPoisonedCacheDegrades`, `::test_rate_limit_load_persisted_degrades_on_poison`, `::TestCtProviderRecursionError` | A stat-then-read size cap has a small TOCTOU window; the `RecursionError` catch is the real backstop |
| CT co-occurrence graph blow-up (reused SAN set across many certs) | `_MAX_GRAPH_ENTRIES`, `MAX_GRAPH_NODES`, `_MAX_EDGE_ISSUER_SAMPLES`, per-cert SAN cap | `test_resilience_hardening::TestInfraGraphEntryBound` | none material |
| CT response flood (entries, SANs, bursts, clusters) | `_MAX_CRTSH_ENTRIES`, `_MAX_SANS_PER_CERT`, `_MAX_CRTSH_CERT_SUMMARY_ENTRIES` (CertSpotter too), `_MAX_PAGES`, burst/cluster caps | `test_hostile_input_bounds::TestCrtshEntryBounds`, `::TestCtGroupingBounds`; `test_crtsh.py` | none material |
| ReDoS via a crafted DNS value + catalog/custom/ephemeral regex | structural validator (`_REDOS_RE` / `_alternation_redos` / `_has_nested_quantifier`) + input-length caps (`_MAX_TXT_MATCH_LENGTH`, `_MAX_CNAME_MATCH_LEN`, `_MAX_SUBDOMAIN_TXT_MATCH_LEN`) | `test_security::TestReDoSPrevention`; `test_hostile_input_bounds::TestDnsParserBounds` (`test_match_txt_oversized_value_is_skipped`, `test_cname_match_is_length_bounded`, `test_subdomain_txt_oversized_is_skipped`) | The validator is a heuristic, not a proof; the length caps are the real backstop (documented) |
| SPF redirect loop / Autodiscover domain flood / XML entity expansion | SPF depth cap 3; `_MAX_AUTODISCOVER_DOMAINS`; defusedxml | `test_hostile_input_bounds::TestDnsParserBounds::test_spf_redirect_loop_terminates`, `::TestAutodiscoverBounds` | none material |
| A hanging or slow source | aggregate `asyncio.wait_for(RESOLVE_TIMEOUT)`; per-query `DNS_QUERY_TIMEOUT`; bounded redirects and cumulative retry sleep | `test_source_fault_injection::test_hanging_source_trips_the_aggregate_timeout`; `test_resilience_hardening::TestHttpBounds` (redirect cap, retry-sleep cap) | The 5 s per-query DNS timeout is exercised through the aggregate path, not asserted in isolation (see Standing gaps) |
| Every boundary x failure-mode (malformed / oversized / wrong-shape / 404 / 500 / timeout / network error / empty) | each HTTP identity source returns a clean `SourceResult`, never raises | `test_hostile_input_bounds::TestSourceFaultMatrix` (the explicit matrix) | none material for the HTTP sources |

## Promise 3: Output is safe to render

**Claim.** Attacker-influenceable strings (CT issuer/SAN names, identity fields,
the BIMI VMC subject, an echoed bad domain) cannot inject terminal escapes,
Rich markup, or markdown structure into the panel, JSON, markdown, or MCP output.

| Mechanism | Proven by | Residual |
|---|---|---|
| `strip_control_chars` (deal-postcondition-pinned) removes all C0/DEL/C1 bytes and caps length, at every source-derived free-text sink | `test_validator::TestStripControlChars`; `test_cert_providers::TestCertDataSanitization`; `test_infra_graph::TestSanAndIssuerSanitization`; `test_bimi_vmc`; `test_ingestion_sanitization` | Printable residue survives by design: a self-logged issuer can still show misleading *printable* text (only control bytes are removed, not deceptive content) |
| `is_safe_dns_name` charset-drops any CT SAN outside `[a-z0-9-._*]` | `test_cert_providers::TestCertDataSanitization`; `test_validator::TestIsSafeDnsName` | A non-DNS-but-printable label is dropped wholesale, not partially shown |
| `escape(strip_control_chars(...))` on error/warning sinks; `_markdown_escape` on markdown | `test_security::TestRenderErrorSanitization`, `::TestOutputInjectionSweep`; `test_formatter::TestMarkdownEscaping` | none material for these paths |
| MCP returns observed DNS/CT strings marked as untrusted data, not instructions | `test_data_not_instructions` | Advisory only: the demarcation instructs the consuming agent but cannot force a downstream model to comply |

## Promise 4: Safe to point at an untrusted target

**Claim.** Running recon against a domain whose DNS an attacker controls does not
turn it into an SSRF vector or an internal-DNS oracle.

| Threat | Mechanism | Proven by | Residual |
|---|---|---|---|
| SSRF to a private/metadata IP (incl. via redirect) | `_SSRFSafeTransport` validates every hop's resolved IP against the blocked-network list | `test_http_advanced::TestSSRFSafeTransport` | DNS rebinding with sub-second TTL is not fully defeated (TOCTOU, documented in `http.py`) |
| SSRF via an attacker-authored BIMI `a=` URL | `_bimi_vmc_url_is_safe` (https, public host, no IP literal, no creds, default port, no redirects) | `test_bimi_vmc::test_refuses_unsafe_a_url` | Host check is suffix/charset-based, not a live public-suffix lookup |
| Internal-DNS leak: attacker CNAME / SPF redirect to an internal name | per-hop `_is_public_dns_name` denylist; CNAME-only walk (no recursive A/AAAA chase); canonical-name guard in `_safe_resolve` | `test_cname_chain_validation` (entry-point, no-A/AAAA-during-walk, canonical guard, SPF/redirect filters) | Documented tradeoff: split-horizon termini are not dropped; one blind query in the type-dependent-answer case still leaves the resolver (see `security-audit-resolutions.md`) |
| Path traversal / symlink overwrite via a crafted cache key | `_safe_cache_path` containment; atomic `mkstemp` (`O_CREAT|O_EXCL`) write | `test_cache_roundtrip::TestCacheDiskOperations` | No dedicated planted-symlink test on the temp name; the random `O_EXCL` name removes the predictable-target vector |

## Promise 5: Honest about uncertainty

**Claim.** recon reports what the public channel can defensibly reveal, with
provenance, and widens its uncertainty rather than overclaiming.

| Mechanism | Where | Residual (the load-bearing honesty) |
|---|---|---|
| The credible interval is evidence-responsive: it widens on sparse/hardened targets, and `sparse=true` flags the passive-observation ceiling | [correlation.md](correlation.md); `test_node_stability_criteria`, the bayesian fuzz/topology suites | The intervals are **evidence-responsive, not empirically calibrated** against ground truth. No passive tool can observe ground truth; recon says so and reserves the word "calibrated" for what frequentist coverage would demonstrate |
| The interval's width absorbs the acknowledged imprecision of the hand-elicited likelihoods: under the CAL8 +/-20% band, the 80% interval contains the correct-world conditional on every node | `validation/interval_coverage.py` (truth from the independent full-joint reference, not the engine); gated by `tests/test_interval_coverage.py`; memo in `validation/interval-coverage.md` | Model-internal perturbation coverage, not ground-truth calibration (CAL13). Priors/CPT rows are not perturbed (tracked as CAL12); coverage against gross misspecification (delta >= 0.5) degrades first on the narrowest-interval node, by design |
| Detections are heuristic, rule-based, and solo-maintained, each carrying a vendor-doc reference for re-verification | `data/fingerprints/*`, `fingerprints.md` | Confident-looking output can still be wrong; treat results as indicators for investigation, not facts |
| Accurate attribution guards: label-aware `cname_target` match, IDNA round-trip check | `test_security::test_cname_target_match_is_label_aware`, `::test_idna_lossy_mapping_rejected` | Dot-less infra markers keep substring semantics by design; a registered homoglyph apex is out of scope |

## Promise 6: The artifact is verifiable

**Claim.** A published release traces back to the exact source and workflow that
produced it, and you can rebuild it to confirm. Full details and a verification
recipe are in [supply-chain.md](supply-chain.md).

| Mechanism | Proven by |
|---|---|
| Reproducible builds (`SOURCE_DATE_EPOCH`), byte-identical wheel + sdist | `ci.yml` `reproducible-build` job (builds twice, compares hashes) |
| Sigstore-signed PyPI attestations (PEP 740) + GitHub build provenance + CycloneDX SBOM + OIDC trusted publishing | `release.yml` (`attest`, `publish-pypi`, `sbom` jobs) |

Residual: full SLSA Level 3 provenance via the reusable generator workflow stays
deferred as disproportionate for a passive single-maintainer tool.

## Standing gaps

Mechanisms that are present in code but whose exact bound is asserted only
indirectly. None is a known defect; each is a place a regression could pass CI,
so they are the proving-test backlog.

- **Production constants not pinned by value.** Several bound tests pass a small
  cap to the unit under test (e.g. `_MaxBytesStream(max_bytes=8192)`) rather than
  asserting the production constant (`_MAX_RESPONSE_BYTES` = 10 MB,
  `RESOLVE_TIMEOUT` = 120 s). The mechanism is proven; the specific value is not.
- **Per-query DNS timeout.** `DNS_QUERY_TIMEOUT` (5 s) is exercised through the
  aggregate-timeout path; no test asserts a slow resolver is bounded at the
  per-query level in isolation.
- **Home-directory YAML overlays.** `profiles.py` and `motifs.py` use the same
  `yaml.safe_load` + guarded-skip + cap pattern as the Bayesian-network loader
  (which is hostile-input fuzzed), but lack a dedicated hostile-YAML test of
  their own. `yaml.safe_load` also does not bound a YAML alias bomb by document
  size; recon's loaders do not recurse into the parsed structure, so the
  reference-shared parse stays cheap, but no test pins that.

These are tracked on the assurance track in [roadmap.md](roadmap.md).
