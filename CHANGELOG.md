# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.1] — 2026-04-14

This release is a correctness and honesty pass driven by real-world runs
against heavily-proxied enterprise targets. Several v0.9.0 outputs were
confidently wrong or framed misleadingly; this release fixes them without
changing the core architecture.

### Fixed

- **DKIM wording overclaim** — insights, exposure gaps, and the exposure
  panel all said "DKIM not configured" when the tool had only checked
  common selector names (mail, selector1, google, k1, etc.). Rewrote to
  "No DKIM selectors observed at common names — actual DKIM status
  unknown" so the absence of a match at known selectors is never
  reported as a configured-or-not claim. 3 files touched.
- **Legacy Provider Residue false positives** — the signal was firing
  on the *current* primary email provider, so a GWS-primary domain
  would show "Legacy Provider Residue: google-workspace" and a
  dual-M365+GWS domain would show both primaries flagged as residue.
  New `exclude_matches_in_primary` field on the Signal schema filters
  matched slugs whose display name appears in either
  `primary_email_provider` or the new `likely_primary_email_provider`.
  When neither primary is known, the signal refuses to fire — a
  residue claim is meaningless without a known primary to be residue
  against.
- **Multi-Cloud miscategorizing CDNs** — Cloudflare, Akamai, Fastly,
  and Imperva were triggering a "Multi-Cloud" signal despite being
  edge/CDN providers, not cloud providers. Split into two signals:
  `Multi-Cloud` (AWS/Azure/GCP/fly.io only) and new `Edge Layering`
  (CF/Akamai/Fastly/Imperva). New `edge_layering` posture rule.
- **Absence engine treating competitors as missing counterparts** —
  `expected_counterparts` entries on Enterprise Security Stack,
  Enterprise IT Maturity, and DMARC Governance Investment listed
  alternative vendors (Proofpoint/Mimecast/Barracuda for one;
  Jamf/Kandji and CrowdStrike/SentinelOne for another). Removed
  those three entries. The two remaining entries (AI Adoption,
  Agentic AI Infrastructure) describe genuine complements.
- **"Split-Brain Email Config" pejorative framing** — renamed to
  "Dual Email Delivery Path" (phrase already used in insights).
  Common deliberate enterprise pattern; previous name read as a
  defect.
- **Confidence overclaiming on degraded sources** — headline confidence
  now downgrades one rung (High→Medium→Low) when any source is in
  `degraded_sources`. Previously "High (4 sources)" would render
  while the bottom note said "crt.sh unavailable" — a self-contradiction.
- **v0.9.0 email topology fields were silently broken** —
  `_detect_mx` in the DNS source never passed `source_type` or
  `raw_value` to `ctx.add()`, so no MX EvidenceRecords were ever
  created. `_compute_email_topology` filters evidence by
  `source_type == "MX"` and consequently always returned
  `(None, None)` on live data. The v0.9.0 `primary_email_provider`
  and `email_gateway` fields have never populated from a real
  lookup. Same issue on Google DKIM detections. Fixed both — MX,
  Exchange DKIM, Google DKIM, and ESP DKIM all now create
  EvidenceRecords with correct source types.
- **v0.9.0 topology fields were never serialized to disk cache** —
  `primary_email_provider`, `email_gateway`, `dmarc_pct`, and the
  new `likely_primary_email_provider` are now persisted and restored
  from `~/.recon/cache/*.json`.
- **Related-domain dump indent regression** — continuation lines on
  the Related: section wrapped to the panel border (column 2)
  instead of the value column (column 14). Same issue on the
  bottom degraded-sources note. Both now wrap cleanly with manual
  column-aware indent.
- **Windows cp1252 Unicode crash** — the panel uses `●` confidence
  dots, `→` arrows, `—` em-dashes, and box-drawing glyphs that
  cp1252 cannot encode. On Windows terminals with the default
  codepage this crashed with `UnicodeEncodeError`. The console
  initializer now reconfigures stdout/stderr to UTF-8 with
  error replacement as a safety net.

### Added

- **`likely_primary_email_provider` — hedged downstream inference**
  for gateway-fronted domains. When MX points to an enterprise email
  gateway (Proofpoint, Mimecast, Symantec, Barracuda, Trellix, Trend
  Micro, Cisco IronPort / Secure Email) and no direct provider
  appears in MX, non-MX evidence (DKIM selectors, identity endpoint
  responses, TXT verification tokens) is scanned for provider slugs.
  When found, the tool emits `likely_primary_email_provider` and
  the Provider line renders as e.g. *"Proofpoint (email gateway,
  likely delivering to Google Workspace + Microsoft 365)"*. Hedged
  on purpose: the word "likely" in the field name is load-bearing.
  Never set when `primary_email_provider` is also set, so the two
  fields do not contradict each other. Plumbed through `TenantInfo`,
  `SignalContext`, the formatter `detect_provider` helper, the
  residue-guard filter, the JSON output, and the disk cache.
- **New `Edge Layering` signal** — fires on 2+ CDN/edge providers
  (Cloudflare/Akamai/Fastly/Imperva) as a deliberate hardening
  indicator. Also added `edge_layering` posture rule.
- **B1: single-source detection annotation in the default panel** —
  service names backed by only one weak evidence type render with a
  dim `*` suffix and a one-line footnote explaining the marker.
  No information loss. Uses the existing v0.3.0 per-detection
  corroboration scoring.
- **B2: related-domains truncation** — default panel shows the first
  10 priority-sorted related domains (via existing HIGH_SIGNAL_PREFIXES
  ordering) with a dim footer `…and N more — use --full for the
  complete list`. Full list still renders behind `--domains` or
  `--full`. Continuation lines and footer manually wrapped to the
  value column.
- **B3: panel color hierarchy for insights** — neutral insights
  render in dim so they read as a scannable secondary column below
  the services list. `Label: value`–shaped insights get a bold-dim
  label with the value in normal-dim. Warnings and hedged insights
  punch through in terracotta; transitions in amber.
- **12 new synthetic regression tests** in `tests/test_hardened_corpus.py`
  across six archetypes (hardened edge, dual-provider baseline, true
  legacy residue, dormant/parked, small-shop-on-CDN, and the new
  likely-primary inference cases). Every fixture uses fabricated
  slugs — no real company names anywhere.
- **6 new regression guards** for `_compute_email_topology` covering
  the likely-primary inference paths.
- 1165 total tests (was 1147), 100% passing.

### Changed

- `TenantInfo.likely_primary_email_provider` — new field, defaults to
  `None`, backward compatible.
- `SignalContext.likely_primary_email_provider` — new field, defaults
  to `None`, backward compatible.
- `Signal.exclude_matches_in_primary` — new field, defaults to `False`,
  backward compatible. When `True`, `_evaluate_single_signal` filters
  matched slugs whose display name appears in the combined
  primary/likely-primary string, and refuses to fire when neither is
  known.
- `_compute_email_topology` now returns a triple
  `(primary_email_provider, email_gateway, likely_primary_email_provider)`
  instead of a pair. Call sites and tests updated.
- `detect_provider()` in `formatter.py` accepts an optional
  `likely_primary_email_provider` parameter and renders the hedged
  "email gateway, likely delivering to X" form when appropriate.
- `google_identity.py` now emits a second `EvidenceRecord` with
  `slug="google-workspace"` (in addition to `google-federated` or
  `google-managed`) so the inference path can see Google as a
  downstream provider on gateway-fronted domains.
- `tests/test_integration.py` — replaced real corporate apex
  references (`microsoft.com`, `google.com`) with RFC-2606 reserved
  `example.com` and `example.org`. Repo is now clean of real
  company names outside of fingerprint detection targets and the
  Contoso/Northwind/Fabrikam fictional-example convention.
- Refined roadmap with a tight "Now / Soon / Later" plan driven by
  real-world findings from hardened enterprise targets.

### Removed

- `expected_counterparts` from Enterprise Security Stack, Enterprise
  IT Maturity, and DMARC Governance Investment (see Fixed above).
  Tests rewritten as regression guards that pin the *absence* of
  those counterparts.

## [0.9.0] — 2026-04-14

### Added

- **Primary Email Provider Detection** — MX-based topology computation distinguishes primary email providers from secondary/legacy detections. New `primary_email_provider` and `email_gateway` fields on TenantInfo. Enhanced Provider line formatting shows email delivery path (e.g., "Microsoft 365 (primary email via Proofpoint gateway)"). New "Email Gateway Topology" and "Legacy Provider Residue" signals. New email topology insights.
- **Negative-Space Analysis** — new `absence.py` module evaluates `expected_counterparts` on signal definitions. When a signal fires but expected companion services are absent, an absence signal is produced with hedged language. 5 built-in signals ship with `expected_counterparts` definitions for out-of-the-box absence detection. Absence signals appear alongside standard signals in all output formats.
- **DMARC Intelligence Expansion** — `rua=mailto:` extraction identifies paid DMARC report vendors (Agari, Proofpoint EFD, OnDMARC, dmarcian, Valimail, EasyDMARC). `pct=` parsing surfaces phased DMARC rollout. 6 new DMARC vendor fingerprints (detection type `dmarc_rua`). New "DMARC Governance Investment" signal. New `dmarc_phased_rollout` posture observation.
- **Ephemeral Fingerprints via MCP** — 4 new MCP tools: `inject_ephemeral_fingerprint` (inject temporary detection patterns), `reevaluate_domain` (re-evaluate cached data with zero network calls), `list_ephemeral_fingerprints`, `clear_ephemeral_fingerprints`. Session-scoped, in-memory, thread-safe. Validated through the same regex/ReDoS pipeline as built-in fingerprints.
- 6 new DMARC vendor fingerprints: Agari, Proofpoint EFD, OnDMARC, dmarcian, Valimail, EasyDMARC. 208 fingerprints total.
- 3 new signals: Email Gateway Topology, Legacy Provider Residue, DMARC Governance Investment. 44 signals total.
- 1 new posture observation: `dmarc_phased_rollout`.
- 1 new module: `recon_tool/absence.py` (absence signal evaluation engine).
- 189 new tests (958 → 1147 total). 6 Hypothesis property-based tests covering all correctness properties.

### Changed

- `TenantInfo` extended with `primary_email_provider`, `email_gateway`, `dmarc_pct` fields.
- `SignalContext` extended with `dmarc_pct`, `primary_email_provider` fields.
- `Signal` dataclass extended with `expected_counterparts` field.
- `SourceResult` extended with `dmarc_pct`, `raw_dns_records` fields.
- `detect_provider()` in `formatter.py` now accepts topology fields for enhanced Provider line formatting. Falls back to existing slug-based detection when topology fields are None (backward compatible).
- `merge_results()` in `merger.py` computes email topology, propagates DMARC metadata, and runs absence evaluation.
- `_detect_email_security()` in `dns.py` extracts `rua=` and `pct=` from DMARC records.
- MCP server now exposes 16 tools (was 12).
- All backward compatible with existing YAML files — new fields default to safe values.

## [0.8.1] — 2026-04-13

### Changed

- README: removed `~` approximation from fingerprint counts — exact 206 fingerprints, 41 signals throughout. Added `--explain` example after the panel. Added multi-step MCP prompt example.
- docs/fingerprints.md: added YAML snippet example for custom fingerprints. Added "Best for" column to detection types table.
- docs/signals.md: added two-pass evaluation note. Updated Layer 1/2/4 tables with all v0.8.0 signals and updated slug lists.
- docs/mcp.md: added multi-step example prompt for deeper analysis workflows.
- docs/roadmap.md: refined "Now" section with intelligence amplification thesis.
- CHANGELOG.md: added standard [Unreleased] section.
- CLAUDE.md: updated stale fingerprint/signal/test counts to current values.

## [0.8.0] — 2026-04-13

### Added

- 12 new fingerprints: CrewAI AID (`crewai-aid`), LangSmith Enterprise (`langsmith`), MCP DNS Discovery (`mcp-discovery`), Container Signing Attestation/Cosign (`cosign-attestation`), Fastly CDN (`fastly`), Fly.io (`flyio`), Railway (`railway`), AutoSPF (`autospf`), OnDMARC/Red Sift (`ondmarc`), dmarcian (`dmarcian`), EasyDMARC (`easydmarc`), Valimail (`valimail`). ~206 fingerprints total.
- 5 enriched fingerprints with additional detections: Sonatype (+OSSRH Maven Central pattern, weight 0.8), Snyk (+alternate site verification), Ping Identity (+PingOne email trust, weight 0.6), CyberArk (+Idaptive CNAME, weight 0.7), Beyond Identity (+authenticator CNAME, weight 0.5).
- 7 new signals: "Agentic AI Infrastructure" (Layer 2 composite), "AI Adoption Without Governance" (contradiction), "AI Platform Diversity" (Layer 2), "Software Supply Chain Maturity" (Layer 2), "DevSecOps Investment Without Email Governance" (contradiction + metadata), "Edge-Native Architecture" (Layer 2), "Enterprise Email Deliverability" (Layer 1). 41 signals total.
- 4 new posture rules: `agentic_ai_detected`, `supply_chain_security_detected`, `edge_compute_detected`, `email_deliverability_management`.
- 62 new tests (896 → 958 total).

### Changed

- GitHub Advanced Security fingerprint pattern corrected from `_github-challenge:.` to `^_github-challenge-` (hyphen, not colon).
- "AI Adoption" signal updated with new agentic AI slugs (crewai-aid, langsmith, mcp-discovery).
- "Enterprise Security Stack" signal updated with beyond-identity.
- "Dev & Engineering Heavy" signal updated with flyio, railway, fastly.
- "Multi-Cloud" signal updated with fastly, flyio.
- `ai_tooling_detected` posture rule updated with new agentic AI slugs.

## [0.7.3] — 2026-04-12

### Changed

- README: restored "the art is in the correlation" in "What it does" section — it's the thesis, not hype.
- README: Limitations section sharpened — more direct about Cloudflare/proxy gaps producing near-empty results, fingerprint staleness being inevitable without community contributions, and confident-looking output sometimes being wrong.

## [0.7.2] — 2026-04-12

### Changed

- README rewritten with honest, grounded tone. Removed "leading platform" positioning, "Explainable Correlation Engine" branding, inflated comparison table, and repetitive zero-credentials copy. Added Limitations section acknowledging project maturity, fingerprint staleness risk, lack of accuracy benchmarks, and heuristic nature of signal rules. Comparison table now honestly notes paid tools typically have broader coverage.
- Roadmap intro simplified — removed aspirational "signal intelligence" branding.
- Fingerprint count normalized to "~190" across all docs (was inconsistent between 187/194).
- Changelog: removed "Explainable Correlation Engine" branding from v0.7.0 entry.

## [0.7.0] — 2026-04-12

### Added

- `--explain` CLI flag — shows why each insight and signal was produced, including matched evidence, fired rules, confidence derivation, and weakening conditions. Works with `--json` (adds `explanations` key), `--md` (adds Explanations section), and `--chain` (per-domain explanations).
- Explanation module (`recon_tool/explanation.py`) — generates `ExplanationRecord` frozen dataclasses with provenance chains for signals, insights, confidence, and posture observations.
- Enhanced YAML signal engine: `contradicts` key (negation logic — suppress signal when specific slugs are present), `requires_signals` key (meta-signals that fire when other named signals are active), `explain` field (curated human-written explanation text per signal/posture rule).
- Enhanced YAML fingerprint engine: `match_mode: all` (AND logic — require all detections to match), detection `weight` (0.0–1.0 evidence strength per detection rule).
- Two-pass signal evaluation: non-meta signals first, then meta-signals against first-pass results. Cycle prevention at load time.
- Weighted `compute_detection_scores()` — incorporates detection weights into per-slug confidence scoring.
- Conflict-aware merge — `MergeConflicts` frozen dataclass on `TenantInfo` tracks disagreements between sources. Surfaced in `--json` (`conflicts` key) and Rich panel (dim annotations with `--explain`).
- 5 new MCP tools: `get_fingerprints` (list loaded fingerprints with filters), `get_signals` (list loaded signals with layer/category filters), `explain_signal` (query signal definition + live evaluation against a domain), `test_hypothesis` (agent proposes theory, gets likelihood + evidence assessment), `simulate_hardening` (what-if exposure re-scoring with hypothetical fixes).
- `explain` parameter on `lookup_tenant` and `analyze_posture` MCP tools — when true, includes structured explanations in JSON response.
- 7 new fingerprints: n8n, Dify, AutoGen, Snyk, GitHub Advanced Security, Sonatype, Beyond Identity. ~190 fingerprints total.
- 5 new signals using v0.7.0 engine features: "Incomplete Identity Migration" (contradicts), "Split-Brain Email Config" (contradicts), "Security Stack Without Governance" (contradicts + metadata), "Complex Migration Window" (meta-signal), "Governance Sprawl" (meta-signal). 34 signals total.
- 173 new tests: unit tests for all engine changes, 10 Hypothesis property-based tests covering all correctness properties, CLI/MCP integration tests, backward compatibility tests. 896 tests total, 84% coverage.

### Changed

- `evaluate_signals()` now uses two-pass evaluation with `contradicts` suppression. File order within each pass is deterministic.
- `Signal` dataclass extended with `contradicts`, `requires_signals`, `explain` fields.
- `DetectionRule` dataclass extended with `weight` field.
- `Fingerprint` dataclass extended with `match_mode` field.
- `_PostureRule` dataclass extended with `explain` field.
- `render_tenant_panel()` accepts `explain` parameter for conflict annotations.
- MCP server now exposes 12 tools (was 7).
- All backward compatible with existing YAML files — new fields default to safe values.

## [0.6.1] — 2026-04-12

### Changed

- README panel alignment fixed (all lines exactly 72 characters).
- All test fixtures and examples use fictional company names only (Contoso, Northwind Traders, Fabrikam). Zero real company names in the repository.
- Validation corpus fixtures are gitignored — never committed.
- Release workflow: `skip-existing: true` prevents PyPI duplicate upload failures on tag re-pushes.

## [0.6.0] — 2026-04-12

### Added

- CertIntelProvider protocol — abstracts certificate transparency querying behind a clean interface. Two implementations: CrtshProvider (primary) and CertSpotterProvider (fallback). Shared filtering helpers ensure behavioral parity.
- CertSpotter fallback — when crt.sh is down (slow, rate-limited, or unreachable), the tool automatically falls back to CertSpotter's free, unauthenticated API. Zero API keys, zero accounts.
- Generalized `degraded_sources` — replaces the single-boolean `crtsh_degraded` with a `degraded_sources: tuple[str, ...]` field on both SourceResult and TenantInfo. Users and agents always know which public data sources were unavailable and how that affects result quality.
- Degraded sources surfaced in all output formats: Rich panel, JSON (`degraded_sources` list + backward-compatible `partial` key), markdown, and MCP text.
- 61 new tests: unit tests for providers, fallback chain, degraded_sources propagation, and 6 property-based tests (Hypothesis). 723 tests total, 84% coverage.
- Validation corpus — integration test runner (`pytest -m integration`) and accuracy report generator (`python -m tests.validation.generate_report` → `docs/accuracy.md`). Fixture files are local-only (gitignored).

### Changed

- `_detect_crtsh` replaced by `_detect_cert_intel` fallback chain in DNS sub-detector.
- `crtsh_degraded` is now a computed `@property` on SourceResult and TenantInfo (backward-compatible).
- Merger collects and deduplicates `degraded_sources` from all source results.
- README: defensive-use-only banner, "organization" replaces "target" throughout, zero-accounts emphasis.
- Legal docs: "What sees your queries" table showing exactly which services see your IP.
- Roadmap: dependency-ordered Now/Soon sections, custom profiles and `--explain` in Soon.

## [0.5.1] — 2026-04-12

### Added

- Full test coverage for defensive security tools: 12 property-based tests (Hypothesis), MCP integration tests, CLI flag tests, import safety test, banned-terms integration test. 660 tests total, 83% coverage.

### Removed

- `--html` output flag — markdown renders everywhere that matters. HTML was bloat for a focused CLI tool.

### Changed

- All test tasks are mandatory, not optional. No skipping.

## [0.5.0] — 2026-04-11

### Added

- `assess_exposure` MCP tool — structured security posture summary with email/identity/infrastructure sections, hardening control inventory, and 0–100 posture score based on publicly observable controls. For defensive security posture assessment only.
- `find_hardening_gaps` MCP tool — identifies missing or weak security configurations with categorized gaps (email, identity, infrastructure, consistency), severity levels, and "Consider ..." recommendations. For defensive security posture assessment only.
- `compare_postures` MCP tool — side-by-side comparison of two domains' security postures with metrics, control differences, and relative assessment. For defensive security posture assessment only.
- `--exposure` CLI flag — runs exposure assessment from the terminal.
- `--gaps` CLI flag — runs hardening gap analysis from the terminal.
- New `recon_tool/exposure.py` module — pure analysis functions operating exclusively on existing TenantInfo data. Zero new network calls. 14 frozen dataclasses for structured output.
- Extended banned terms enforcement — all new tool output validated against 16 banned terms to ensure neutral, defensive language throughout.
- Legal documentation updated with "Defensive Security Assessment Tools" section covering intended use cases, data source constraints, and language policy.

### Changed

- MCP server now exposes 7 tools (was 4): `lookup_tenant`, `analyze_posture`, `chain_lookup`, `reload_data`, `assess_exposure`, `find_hardening_gaps`, `compare_postures`.

## [0.4.1] — 2026-04-11

### Changed

- Added PyPI trusted publishing via GitHub Actions (OIDC, no API tokens).
- Added package metadata: classifiers, keywords, project URLs for PyPI listing.
- Fixed duplicate file warnings in wheel build by removing redundant `force-include`.

## [0.4.0] — 2026-04-11

### Added

- `--csv` output for batch mode — flat CSV with one row per domain. Columns: domain, provider, display_name, tenant_id, auth_type, confidence, email_security_score, service_count, dmarc_policy, mta_sts_mode, google_auth_type.
- Lightweight local disk cache — `~/.recon/cache/` with configurable TTL (default 24h). CLI flags: `--no-cache` to bypass, `--cache-ttl` to override. JSON files on disk, lazy eviction, no external dependencies.
- `recon mcp` subcommand — start the MCP server from the CLI instead of `python -m recon_tool.server`.
- `recon doctor --fix` — scaffolds template `~/.recon/fingerprints.yaml` and `~/.recon/signals.yaml` with inline YAML comments explaining the format.

### Changed

- Inference language tightened across insights and signals. Derived claims now use hedged language ("suggests," "indicators," "likely") instead of declarative phrasing. Factual observations (DMARC values, DKIM presence, email security scores) remain declarative.
- Removed `_preprocess_args()` sys.argv mutation hack. Domain shorthand routing (`recon contoso.com`) now uses a custom Typer group with `resolve_command()` override — cleaner, safer for library imports, no global state mutation.
- `_SUBCOMMANDS` now includes `"mcp"`.
- Mutual exclusion enforced for output format flags (`--json`, `--md`, `--csv`).

## [0.3.0] — 2026-04-11

### Added

- Google Workspace identity routing — new `GoogleIdentitySource` detects federated vs. managed auth by querying Google's public login flow. Extracts IdP name (Okta, Ping, Entra, etc.) for federated domains. Produces `google-federated`/`google-managed` slugs.
- Google Workspace CNAME module probing — detects active GWS modules (Mail, Calendar, Docs, Drive, Sites, Groups) via `ghs.googlehosted.com` CNAME resolution. Concurrent queries for all 6 prefixes.
- BIMI/VMC corporate identity extraction — fetches VMC certificates from BIMI `a=` URLs and extracts legally verified organization name, country, state, locality. Falls back to regex parsing when `cryptography` library is unavailable.
- Google site-verification token extraction — captures `google-site-verification` token values from TXT records for cross-domain organizational relationship mapping.
- MTA-STS policy fetch — when `_mta-sts` TXT record is found, fetches the policy file and extracts the mode (enforce/testing/none). Adds `mta-sts-enforce` slug for enforcing domains.
- TLS-RPT detection — detects `v=TLSRPTv1` records at `_smtp._tls.{domain}` with `tls-rpt` slug.
- Enhanced CSE config probing — extracts KACLS URL and multiple key service provider names from Google Workspace CSE configuration.
- Evidence traceability — new `EvidenceRecord` frozen dataclass captures source type, raw value, rule name, and slug for every detection. Propagated through the merge pipeline to `TenantInfo`. Included in `--json` output and `--verbose` display.
- Confidence separation — dual confidence model: `evidence_confidence` (how many sources contributed) and `inference_confidence` (strength of logical chain). Backward-compatible `confidence` field = min of both.
- Per-detection corroboration scoring — each detected slug gets a confidence score (high/medium/low) based on how many independent record types corroborate it.
- Fingerprint metadata enrichment — `provider_group` and `display_group` fields on fingerprint YAML entries. Formatter uses these for categorization, falling back to keyword heuristics.
- Cross-domain site-verification correlation in chain mode — domains sharing identical `google-site-verification` tokens are surfaced as organizationally related.
- 5 new Google Workspace signals: Google Workspace Full Suite, Google Federated Identity, Google MTA-STS Enforcing, plus updates to Google-Native Identity and Google Cloud Investment.
- 4 new posture rules: google_federated_identity, google_managed_identity, mta_sts_enforcing, tls_rpt_configured.
- Google Workspace insight generators: federated/managed identity insights, module summary insights.
- New data models: `EvidenceRecord`, `BIMIIdentity`. Extended `SourceResult`, `TenantInfo`, `Fingerprint` with new fields.
- 98 new tests (506 → 604 total). Test coverage 84%.

### Changed

- `default_pool()` now includes `GoogleIdentitySource` (5 sources total).
- `merge_results()` propagates evidence, computes dual confidence, detection scores, and merges Google auth/BIMI/MTA-STS/site-verification data.
- `build_insights_with_signals()` accepts `google_auth_type` and `google_idp_name` parameters.
- `format_tenant_dict()` includes all new fields in JSON output.
- `format_tenant_markdown()` includes Google Workspace section and dual confidence.
- `render_tenant_panel()` shows GWS auth/modules, verbose evidence chains and detection scores.
- `lookup_tenant` MCP tool text format includes GWS auth and module summary.
- `_detect_email_security()` now also queries TLS-RPT, fetches MTA-STS policy, and parses BIMI VMC.
- `_detect_txt()` extracts site-verification tokens and creates evidence records.
- Fingerprints YAML: added `provider_group`/`display_group` to Microsoft 365, Google Workspace, and other key entries. Added TLS-RPT fingerprint.
- 29 signals (was 26). 22 posture rules (was 18).

## [0.2.0] — 2026-04-11

### Added

- Certificate intelligence — crt.sh metadata extraction (issuance velocity, issuer diversity, cert age, top issuers) from the existing crt.sh JSON response. No additional HTTP requests. Surfaced in panel, JSON, and markdown output.
- Metadata-aware signal engine — signals can now match on `dmarc_policy`, `auth_type`, `email_security_score`, `spf_include_count`, and `issuance_velocity` via YAML `metadata` conditions. Supports slug-only, metadata-only, and conjunction signals. 23 → 26 signals (4 layers).
- Neutral posture analysis — new `--posture` flag and `analyze_posture` MCP tool. Produces factual observations about domain configuration (email, identity, infrastructure, SaaS footprint, certificates, consistency) without attack/defense framing. YAML-driven rules in `data/posture.yaml` with `~/.recon/posture.yaml` additive override.
- Delta mode — `--compare previous.json` compares a live lookup against a previous JSON export. Surfaces added/removed services, slugs, signals, and scalar field changes (auth type, DMARC, confidence, domain count). Panel output with +/- markers, JSON output with structured diff.
- Recursive domain chaining — `--chain --depth N` (max 3) follows related domains via CNAME/CT breadcrumbs using BFS. 50-domain cap, visited-set deduplication, aggregate timeout. New `chain_lookup` MCP tool.
- 3 new metadata-aware signals: Federated Identity with Complex Email Delegation, Active Email Sending with Minimal Security, High Certificate Issuance Activity.
- 18 posture observation rules across 6 categories.
- 7 new frozen dataclasses: `CertSummary`, `MetadataCondition`, `SignalContext`, `Observation`, `DeltaReport`, `ChainResult`, `ChainReport`.
- 51 new tests (455 → 506 total). Test coverage 83%.

### Changed

- `--full` now implies `--posture` in addition to `--services`, `--domains`, `--verbose`.
- `evaluate_signals()` now accepts a `SignalContext` instead of positional args. All callers updated.
- "Security Gap — Gateway Without DMARC Enforcement" signal moved from hardcoded Python check to YAML metadata conditions.
- `reload_data` MCP tool now also clears posture rule cache and reports posture rule count.
- README updated: broader audience description, new feature table rows, new CLI examples, new MCP tools listed.
- Roadmap updated: completed items marked, new future items added.

## [0.1.3] — 2026-04-11

### Added

- Common subdomain probing — ~35 high-signal prefixes (auth, login, sso, shop, api, status, cdn, etc.) are probed directly via DNS CNAME lookups. Works even when crt.sh is down.
- 30 new CNAME-based fingerprints for SaaS services discovered via subdomain CNAMEs: Okta (CNAME), Auth0, OneLogin, Salesforce Marketing Cloud, AWS ELB/S3/Elastic Beanstalk, Azure Front Door, Google Cloud Run/App Engine, Zendesk/Freshdesk (hosted), Contentful, Braze, Segment, Statuspage, LaunchDarkly, Cloudinary, Imgix, Optimizely, WalkMe, and more (156 → 186 total).
- crt.sh degraded notice — when crt.sh is unreachable, a subtle note appears in panel, markdown, and JSON output (`"partial": true`) so users know results may be incomplete.
- Lightweight subdomain enrichment — subdomains get CNAME+TXT-only lookups (2 queries each) instead of full DNS fingerprinting (~20 queries each), keeping enrichment fast.

### Changed

- crt.sh subdomain cap raised from 20 to 100, with signal-based prioritization (auth/login/shop/api subdomains first, deep internal subdomains last).
- Enrichment cap raised from 10 to 25, with priority sorting so high-signal subdomains survive the cap.
- Two-tier enrichment: subdomains get lightweight CNAME+TXT lookups, separate domains get full DNS fingerprinting.
- Updated 8 signal rules to include new CNAME-detected slugs (imperva, auth0, onelogin, salesforce-mc, aws-elb, aws-s3, gcp-app, azure-fd, optimizely, walkme, braze, iterable, customerio, launchdarkly, contentful, etc.).

## [0.1.2] — 2026-04-11

### Added

- Google Workspace source — passive CSE config probing (`cse.{domain}/.well-known/cse-configuration`) for detecting Client-Side Encryption and external key managers.
- Google DKIM attribution — `google._domainkey` now adds the `google-workspace` slug, so Google Workspace is detected even when MX points to an email gateway (Proofpoint, Mimecast, Trend Micro, etc.).
- 4 new signal rules: Google-Native Identity, High-Security Posture (CSE), Google Cloud Investment, Dual Email Provider (13 → 24 total).
- Custom signals support via `~/.recon/signals.yaml` (additive, mirrors fingerprint extensibility).
- Certificate transparency integration via crt.sh for passive subdomain discovery.
- Expanded DKIM selector coverage — now checks common ESP selectors (Mailchimp, SendGrid, Mailgun, Postmark, Mimecast) in addition to Exchange and Google.
- SRV record detection for Microsoft Teams (legacy SIP/federation), XMPP, CalDAV, CardDAV.
- 13 new fingerprints: Box, Egnyte, Glean, Datadog, New Relic, PagerDuty, Render, Ping Identity, CyberArk, Lakera, Cato Networks, Rippling, Deel (143 → 156 total).
- `recon doctor` now checks crt.sh connectivity, signal database loading, and custom signals path.
- "Why recon?" comparison table in README.
- Expanded MCP Server section with setup steps, tools table, and config file locations per client.
- `CLAUDE.md` for project context.
- `CHANGELOG.md`, `CONTRIBUTING.md`.
- `examples/` folder with sample JSON output and batch file (all fictional data).
- GitHub Actions CI workflow (Python 3.10–3.13, lint, type check, tests).

### Changed

- Confidence scoring — M365 domains now reach High when OIDC tenant ID is corroborated by UserRealm (display name, auth type, or tenant domains). Previously required 2+ sources returning the same tenant ID, which never happened in practice.
- Non-M365 confidence — domains with 8+ DNS services and 2+ successful sources now reach High. Thresholds adjusted (was: 5 services for Medium, High unreachable).
- Skype for Business / Lync → Microsoft Teams — SRV records `_sip._tls` and `_sipfederationtls._tcp` pointing to `lync.com` now labeled as "Microsoft Teams" (deduplicated with CNAME-based detection). Microsoft retired Skype for Business Online in July 2021.
- Dual provider insight — shortened from "Hybrid/migration signal: Google email + Microsoft services detected" to "Dual provider: Google + Microsoft coexistence". No longer styled as a warning.
- Panel color palette — muted, modern tones replacing harsh ANSI primaries. Labels use `dim` instead of `bold`. Panel border is `dim`. Confidence colors: sage green (High), sky blue (Medium), terracotta (Low).
- Panel alignment — services and insights now use consistent label:value column alignment. Service continuation lines align under the first service name. Long insights word-wrap within the panel.
- All README examples now use fictional companies (Northwind Traders, Contoso, Fabrikam).
- README tagline updated to be more precise and humble.
- Panel output: fixed width (80 chars), related domains now dim instead of cyan.
- Updated Enterprise Security Stack, Zero Trust Posture, and Enterprise IT Maturity signals to include new security slugs.

## [0.1.0] — 2026-04-10

### Added

- Initial release.
- Domain intelligence CLI (`recon lookup`, `recon batch`, `recon doctor`).
- MCP server with `lookup_tenant` and `reload_data` tools.
- Three concurrent data sources: OIDC Discovery, GetUserRealm + Autodiscover, DNS records.
- 143 SaaS/service fingerprints in `data/fingerprints.yaml` across 14 categories.
- Signal intelligence engine with 3-layer evaluation (single-category, cross-category composites, consistency checks).
- Email security scoring (0–5) based on DMARC, DKIM, SPF strict, MTA-STS, BIMI.
- Related domain auto-enrichment from CNAME breadcrumbs.
- Custom fingerprint support via `~/.recon/fingerprints.yaml`.
- Rich terminal output with bordered panels, colored signals, and provider detection.
- Output formats: default panel, `--json`, `--md`, `--services`, `--full`, `--sources`.
- Batch mode with configurable concurrency (1–20) and ordered output.
- Input normalization (URLs, schemes, www prefix, paths, whitespace).
- SSRF protection in HTTP transport.
- Retry with exponential backoff on 429/503 responses.
- Structured exit codes (0, 2, 3, 4).
- `defusedxml` for safe XML parsing.
- Strict type checking with Pyright, linting with Ruff.
