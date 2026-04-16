# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.3] — 2026-04-15

This release is the *Sparse-Target Amplification + UX Refinement* pass.
Themes: (1) extract more hedged signal from the same passive sources —
especially on heavily-proxied, minimal-DNS, managed-auth targets where
older releases went silent; (2) redesign the default CLI output so
professional users never feel like they're looking at hobbyist-grade dump
output; (3) validation-driven fixes from real-world runs against EDU,
nonprofit, religious, and sparse commercial targets. Everything stays
within the passive / zero-creds / zero-additional-network invariants.

### Validation-driven refinements

- **Categorized Services refinements**:
  - `"AWS Route 53"` renders as `"AWS Route 53 (DNS)"` under Cloud so
    the row can't be misread as "primary cloud = AWS". Same treatment
    for `azure-dns`, `gcp-dns`, CDN providers (`(CDN)`),
    edge/serverless platforms (`(edge)`), and WAFs (`(WAF)`).
  - `google-managed` / `google-federated` slugs render as
    `"Google Workspace (managed identity)"` / `"(federated identity)"`
    instead of the raw slug.
  - CAA issuer fingerprints collapse to one `"CAA: N issuers
    restricted"` entry instead of four separate rows overwhelming
    Security.
  - `"CAA: "` prefix stripped when a CAA-derived fingerprint is
    classified in a non-Security category (e.g.
    `"CAA: AWS Certificate Manager"` → `"AWS Certificate Manager"`
    in Cloud).
  - Exchange Autodiscover classified as Email instead of Other.
  - Verification-token artefacts (`"(site verified)"`,
    `"(domain verified)"`, `"Domain Connect (…)"`) filtered from
    the categorized Services block — they're ownership receipts,
    not deployed products.
  - Identity row dropped when its only entry is a
    `"<provider> (managed identity)"` echo of an Email row.
- **Insights dedup and curation**:
  - Four overlapping dual-provider signals (`Dual provider`,
    `Dual Email Provider`, `Dual Email Delivery Path`,
    `Secondary Email Provider Observed`) collapse to one canonical
    line.
  - Three overlapping AI-adoption signals collapse to one
    `"AI Adoption Without Governance"` line when the governance
    version fires.
  - On sparse targets (`Email security 0/5` / `1/5` / `2/5`), the
    subsequent `"No DMARC record"`, `"No DKIM selectors"`, and
    `"DMARC: none"` lines are dropped as redundant — the score
    line already says it.
  - `"Cloud-managed identity indicators (Entra ID native)"` only
    fires on pure M365 targets (no Google Workspace present) —
    on dual-provider targets the Auth line already says
    `"Managed (Entra ID + Google Workspace)"` so the insight
    would be pure restatement.
  - Meta-signals (`requires_signals` only, no candidates) that
    fire with an empty `matched` list — for example
    `"Complex Migration Window"` — render as a bare name instead
    of a `"Name: "` dead-end with nothing after the colon.
  - Raw slugs in signal insight text now humanize through a
    ~90-entry map: `"sendgrid, mailchimp"` → `"SendGrid, Mailchimp"`,
    `"crewai-aid"` → `"CrewAI"`, `"google-managed"` →
    `"Google Workspace (managed)"`, etc.
  - Variant-slug dedup: when a signal's matched list carries both
    `"google-workspace"` and `"google-managed"`, the variant
    collapses into the parent so the insight doesn't read
    `"Google Workspace, Google Workspace (managed)"`.
- **Sparse-signal observation**: new hedged two-sided insight that
  fires when service density is low and the target isn't an M365
  tenant. States explicitly: *"Sparse public signal — few
  observable records beyond MX and identity. Consistent with a
  small organization, a parked or dormant domain, or a
  heavily-proxied target. Observation, not a verdict."* This is
  the explicit answer to "why is this panel thin" that the
  previous output left the user guessing about.
- **Provider line / Auth line consistency**:
  - Slug-only fallback in `detect_provider` always adds the
    `"(primary)"` qualifier now (was inconsistent before —
    topology path labelled, fallback path didn't). Multi-provider
    fallback follows the same `"primary + secondary"` format as
    the topology path.
  - Auth line `"Unknown + Managed (GWS)"` bug: `GetUserRealm`
    returns `NameSpaceType=Unknown` for non-M365 domains; that
    value now gets filtered at display time so Google-only
    domains read `"Managed (Google Workspace)"` instead of
    leaking the "Unknown" token.
  - Auth line `"(GWS)"` abbreviation replaced with
    `"(Google Workspace)"` in the mismatched-auth branch (the
    same-auth compound branch already used the full name —
    inconsistent before).
  - Auth line `"Entra ID"` claim only fires when `microsoft365`
    is in `slugs`, not just when `tenant_id` is set. A domain
    with a registered but inactive M365 tenant no longer gets
    a false "Entra ID" label on the Auth line.
- **Panel layout**:
  - Hero header shows `display_name` once — when it falls back to
    the raw domain (no company name extractable), the duplicated
    hostname line that looked like a bug is gone.
  - Long Provider-line values wrap with an explicit continuation
    indent matching the label column, instead of Rich's default
    column-0 wrap that made `"…Google \\nWorkspace"` ugly.
  - Panel width reduced from 80 → 78 to avoid terminal
    wrap-to-next-line artefacts at the 80-char boundary.
  - Confidence line single-space between dots and label (was
    double-space).
- **Degraded-sources Note reframing**:
  - Two tiers now: **info tone** (default color) when only CT
    sources were degraded AND a CT fallback successfully reached
    another provider (reads as a routine fallback event, not a
    warning); **warning tone** (yellow) when a non-CT source is
    down or every CT provider failed.
  - When CT fallback succeeded with zero subdomains, the Note
    line is suppressed entirely — the outcome is identical to a
    clean run on a domain with no related CT data, so mentioning
    the fallback every time was persistent noise.
  - Wording changed from `"Some sources unavailable"` (false
    alarm when fallback recovered) to `"CT fallback: crt.sh →
    certspotter (N subdomains)"` in the recovered-but-informative
    case, and `"All CT providers unavailable"` when genuinely
    failed.
- **Confidence downgrade logic**:
  - v0.9.2 auto-downgraded confidence on any `degraded_sources`.
    v0.9.3 skips the downgrade when the ONLY degraded sources
    are CT providers AND a CT fallback successfully recovered
    data. Previously, every domain looked up while crt.sh was
    flaking got stuck at `medium` even when the fallback chain
    fully recovered.
- **JSON schema hole fixed**: `format_tenant_dict` now emits the
  `slugs` field explicitly. Downstream tooling used to have to
  reconstruct slug sets from the `detection_scores` field because
  the top-level `slugs` field was missing from the output.
  Also added `cloud_instance`, `tenant_region_sub_scope`,
  `msgraph_host`, and `lexical_observations` to the emitted
  dict — they were on `TenantInfo` but not surfaced in
  `--json`.

### Docs and roadmap

- **Roadmap rewritten** (`docs/roadmap.md`): collapsed from the
  original 191-line, four-release (`v0.9.3 → v0.9.4 → v0.9.5 →
  v1.0`) gold-plated plan into a tighter ~150-line priority-
  ordered list. CT source resilience promoted from "Later/maybe"
  to `What's next #1` — three-provider fallback chain + local
  per-domain JSON cache with 7-day TTL. Community fingerprint
  pipeline elevated from "Later/maybe" to 1.0 scope.
  `--confidence-mode strict` flag added as a future item for the
  hedging-on-dense-evidence complaint. Bayesian evidence fusion,
  property-graph core, counterfactual simulation, temporal CT
  all demoted to "Post-1.0 ideas". Forward dates and version-
  number sequencing removed per feedback. 1.0 metrics made
  explicit (≥80% signal coverage, zero unhedged assertions on
  sparse-evidence fixtures, MCP idempotent/cache-aware, stability
  tags on every public surface).
- **README example panel updated** to the v0.9.3 hero layout. The
  old bordered-panel example no longer matched reality — a new
  user reading the README would see an example format the tool
  doesn't produce anymore.

### Added — Sparse-target inference

- **`positive_when_absent` absence-engine extension + hedged
  hardening observations.** The `Signal` schema gains a new
  `positive_when_absent` field. When a parent signal fires AND none
  of the listed adversary-friendly / consumer-SaaS slugs are
  detected, the absence engine emits a hedged two-sided positive
  observation: *"Edge Layering — Hardening Pattern Observed: fits a
  deliberately hardened target, a dormant / parked domain, or a
  small shop behind an edge proxy. Hedged observation, not a
  verdict."* The v0.9.3 `Edge Layering` signal carries a 14-slug
  exclusion set (`slack`, `notion`, `atlassian`, `dropbox`, `canva`,
  `hubspot`, `salesforce`, `zoom`, `miro`, `airtable`, `intercom`,
  `mailchimp`, `monday`, `clickup`) so a hardened-enterprise proxy
  target finally gets a positive reading without any confident
  verdict. Wired through `merger.build_insights_with_signals`,
  `cli._build_explanations`, and `server._lookup_tenant_json_with_explain`
  so the hardening observation shows up in every `--explain` output
  path. 14 unit tests pin the invariant.
- **CT subdomain lexical taxonomy** (`recon_tool/lexical.py`). A
  pure-Python rule parser that classifies CT-discovered subdomains
  into environment (`dev-`, `stg-`, `uat-`, `prd-`, `sbx-`), region
  (`us-east`, `eu-west`, `ap-southeast`, `apne1`), and tenancy-shard
  (`t-1234`, `org-acme`, `tenant-xyz`) taxonomies. No ML, no bundled
  embeddings, no generated candidates. Emits hedged
  ``LexicalObservation`` entries on the standard insights list:
  "Mature environment separation pattern observed (3 env-prefixed
  subdomains e.g. dev, stg, prod) — consistent with multi-environment
  deployment pipelines. Observation, not a verdict." A threshold of
  `MIN_MATCHES=2` prevents single-subdomain coincidences from firing
  the signal; sample labels are capped at 3 so `--explain` shows
  evidence without flooding. 30 unit tests cover env/region/shard
  classification, label boundary rules, and observation hedging.
- **OIDC tenant metadata enrichment** (`sources/oidc.py`). The
  `parse_tenant_info_from_oidc` parser now extracts the Microsoft
  extensions `cloud_instance_name`, `tenant_region_sub_scope`, and
  `msgraph_host` from the discovery response — fields that were
  already in the JSON we fetched but silently discarded. These
  distinguish commercial M365 (`microsoftonline.com`), US Government
  Community Cloud (`microsoftonline.us` + `GCC`), GCC High / DoD
  (`microsoftonline.us` + `DOD`), Azure China 21Vianet
  (`partner.microsoftonline.cn`), and Azure B2C (`*.b2clogin.com`)
  tenancies. Surfaced in `TenantInfo.cloud_instance`,
  `TenantInfo.tenant_region_sub_scope`, and `TenantInfo.msgraph_host`;
  rendered by a new `_sovereignty_insights` generator in
  `insights.py` as a hedged insight line ("Likely US Government
  Community Cloud (GCC) tenant (observed
  cloud_instance=microsoftonline.us)"). 13 unit tests pin the
  detection rules and the hedging invariants.
- **Shared verification token clustering**
  (`recon_tool/clustering.py`, new module). In-memory, batch-scope,
  never persisted. When two or more domains in a single `recon batch`
  run share the same `google-site-verification`, `MS=`,
  `atlassian-domain-verification`, Zoom, or similar TXT token, each
  domain's JSON output gains a `shared_verification_tokens` array
  with per-token peer attribution. Exposed programmatically via a
  new read-only `cluster_verification_tokens` MCP tool that accepts
  a list of domains and returns the cluster map from cached
  `TenantInfo` — zero extra network calls. Shared tokens are
  **hedged "possible relationship (observed)"** signals, never
  acquisition verdicts — a reused token implies a shared SaaS
  account operator, not corporate identity. 21 unit tests cover
  normalization, symmetry, multi-peer clusters, and deterministic
  ordering.
- **Custom profile templates + `--profile` flag**
  (`recon_tool/profiles.py`, new module). YAML files in
  `~/.recon/profiles/*.yaml` (or the built-in `data/profiles/`
  directory) define a lens: `category_boost` multipliers,
  `signal_boost` per-signal multipliers, `focus_categories` filters,
  `exclude_signals` blocklists, and a `prepend_note` header.
  Profiles are additive-only — they reweight and reorder existing
  observations, never add new intelligence. Six built-in profiles
  ship in `data/profiles/`: `fintech`, `healthcare`, `saas-b2b`,
  `high-value-target`, `public-sector`, `higher-ed`. The CLI gains `--profile
  <name>` on the lookup command; the MCP `analyze_posture` tool
  gains an optional `profile` argument. Custom profiles override
  built-ins when the name matches — one of the few exceptions to
  the usual additive-only invariant, on the grounds that profiles
  are explicitly user-facing lenses and explicit override is the
  expected mode. 25 unit tests cover built-in discovery, custom
  profile loading, invalid YAML handling, boost multipliers,
  category filtering, and deterministic ordering.
- **DMARC aggregator fingerprinting** — four new vendors added to
  the existing `dmarc_rua` detection pipeline: URIports,
  DMARC Advisor, PowerDMARC, Mimecast DMARC Analyzer. Total
  fingerprint count now **227** (was 208). The `DMARC Governance
  Investment` signal's `requires.any` list was expanded to cover
  the new slugs, so RUA addresses pointing to these vendors now
  fire the governance-maturity signal end-to-end.
- **EDU / nonprofit / marketing fingerprints** — 15 new
  fingerprints: Canvas LMS, Blackboard, Moodle, Ellucian
  Banner, Handshake, Top Hat (higher-ed LMS/SIS), Dynamics 365
  Marketing, Salesforce Marketing Cloud (SFMC), Emma, iContact,
  MailerLite (marketing automation), VMware Cloud, Salesforce
  NPSP, Blackbaud, Classy (nonprofit CRM/fundraising).
  TXT-verification detection merged into existing Netlify and
  WP Engine entries.
- **Exchange on-prem / hybrid detection**
  (`dns._detect_exchange_onprem`). Probes `owa.`, `outlook.`,
  `exchange.`, `mail-ex.`, `webmail.`, `autodiscover.` subdomains.
  `autodiscover` uses A-only resolution (not CNAME) to avoid
  M365 false-positives — M365 autodiscover is CNAME to
  `outlook.com`. Emits `exchange-onprem` slug. Wired into the
  parallel `asyncio.gather` detector set.
- **Federated SSO hub detection** (`dns._detect_idp_hub`).
  Probes 15 identity-provider subdomain prefixes (`shibboleth`,
  `weblogin`, `idp`, `wayf`, `sp`, `sso`, `saml`, `cas`,
  `raven`, `webauth`, `harvardkey`, `kerberos`, `okta`, `adfs`,
  `federation`) for A records. Emits `federated-sso-hub`,
  `okta-sso-hub`, or `adfs-sso-hub` slugs depending on match.
- **SPF redirect chain following** (`dns._follow_spf_redirect`).
  Follows `redirect=` directives in SPF records up to 3 hops,
  collecting additional SaaS fingerprint matches from the
  redirect targets. Silent failure via try/except.
- **A → PTR cloud hosting detection**
  (`dns._detect_hosting_from_a_record`). Resolves the apex A
  record, then performs a PTR lookup on the resulting IP.
  Pattern table covers AWS EC2/ELB, Azure VM, GCP Compute,
  Linode, DigitalOcean, Hetzner, OVH, and Vultr.
- **Higher-ed profile** (`data/profiles/higher-ed.yaml`). Sixth
  built-in posture profile for universities, colleges, research
  institutions, and academic computing. Boosts identity (1.6×),
  email (1.5×), infrastructure (1.3×). Prioritises federated
  identity, LMS detection, email governance. Excludes GTM
  signals that don't apply to universities.
- **MX always-emit for `has_mx_records` plumbing**. `_detect_mx`
  now emits an `EvidenceRecord` for every MX host even when no
  fingerprint matches, so the downstream `has_mx_records` check
  works regardless of fingerprint coverage.
- **Email security scoring honesty**. The email security score
  now requires MX-backed evidence (`primary_email_provider`,
  `likely_primary_email_provider`, `dmarc_policy`, or
  outbound-email slug) before scoring. Domains with zero email
  infrastructure no longer get a misleading `0/5 weak` label.
  Score `0` with monitoring records reads "DMARC monitoring
  mode, SPF soft/neutral — no strict controls" instead of
  "no protections detected".
- **Provider "account detected" variants**. When identity
  endpoints show a registered account but MX records don't
  confirm active email delivery, the provider line now reads
  `"(account detected, no MX)"` or `"(account detected,
  custom MX)"` instead of claiming the provider as primary.
- **Explanation DAG serialization** (`explanation.build_explanation_dag`).
  Produces a JSON-serializable provenance DAG from any list of
  `ExplanationRecord` instances: node types `evidence`, `slug`,
  `rule`, `signal`, `insight`, `observation`, `confidence`; edge
  types `detected-by`, `contributes-to`, `fired`. Every terminal
  node is reachable from at least one evidence node via a short
  path (asserted by the v0.9.3 property-based harness). `--explain
  --json` on the CLI and the MCP `lookup_tenant` with `explain=true`
  both emit the DAG under a new `explanation_dag` key alongside
  the existing flat `explanations` list — old consumers stay
  working, new consumers get the structured view. 17 unit tests
  pin the shape, the node types, the edge semantics, and
  determinism.
- **Property-based hedging regression harness**
  (`tests/test_v093_hedging_invariants.py`). Hypothesis-driven
  fuzz testing that asserts five hedging invariants against
  random slug subsets and random OIDC metadata: (1) every
  `positive_when_absent` output is hedged and two-sided; (2) the
  emitted SignalMatch name carries the `"Hardening Pattern
  Observed"` suffix; (3) sovereignty insights never claim
  certainty; (4) the signal pipeline never raises or emits
  duplicate names; (5) every absence signal references a
  legitimately-firing parent. Plus a static pass over every
  loaded signal to reject forbidden confident-verdict language
  (`definitely`, `proven`, `confirmed `, `guaranteed`). Runs in
  under 5 seconds on default settings so it's always on. This is
  the mechanical floor that makes every other v0.9.3 item safe to
  ship — a future PR that reintroduces confident-wrong language
  fails CI before merge.

### Added — UI/X refinements

- **Default panel redesign** (`formatter.render_tenant_panel`).
  Complete visual rewrite of the lookup output. The old bordered
  Rich Panel with an 80-column frame is replaced by a plain-text
  hero layout: company name in bold, apex domain on a dim second
  line, a horizontal rule, then a 13-column label / value fact
  block (Provider, Tenant, Auth, Cloud, Confidence), then a
  hierarchical Services section broken into seven display
  categories (Email, Identity, Cloud, Security, AI, Collaboration,
  Other), then a compact 1–2 line High-Signal Related Domains
  section, then curated Insights, and — only when sources are
  actually degraded — a subtle yellow Note line. `--full`,
  `--verbose`, `--explain`, and `--domains` add additional
  sections (full tenant_domains list, evidence chain, conflict
  annotations, cert summary) after the core layout without
  breaking its structure.
- **Disciplined color palette**: subtle cyan/teal for section
  headers (`Services`, `High-signal related domains`, `Insights`),
  green **only** when confidence is `High`, default text for
  Medium/Low confidence (no alarmist yellow, no red, no
  high-chroma anywhere), subtle yellow for the degraded-sources
  Note line (only when it appears). Graceful monochrome fallback
  — terminals without color support still render the full layout
  as plain text.
- **Categorized services classifier**. A 120+ slug → category
  lookup table (`_CATEGORY_BY_SLUG`) gives every detected slug a
  deterministic home in one of the seven display categories.
  Services whose slug isn't in the table fall through to a
  prefix-based classifier (`DMARC`/`DKIM`/`SPF` → Email,
  `DNS:`/`CDN:`/`Hosting:` → Cloud, etc.). Pass-2 dedup via
  lowercase-prefix matching prevents the same detection from
  appearing twice under two different display names (e.g.
  `"Atlassian"` + `"Atlassian (Jira/Confluence)"`).
- **Curated Insights filter** (`formatter._curate_insights`).
  Drops the repetitive laundry-list entries the old panel dumped
  verbatim (`Security stack: …`, `Infrastructure: …`,
  `PKI: …`, `Google Workspace modules: …`, mid-size org-size
  hints). Kept: signal firings, hardening observations,
  sovereignty hints, email security scores, topology notes.
- **Compact related-domains block**. Picks up to 8 high-signal
  subdomains (prefixes `login.`, `sso.`, `auth.`, `idp.`, `api.`,
  `admin.`, `portal.`, `dashboard.`, `support.`, `status.`,
  `app.`, `cdn.`) and displays them as a wrapped 1–2 line comma
  list with a `(N total — M more, use --full to see all)`
  footer. The old panel's 10-entry vertical list is replaced
  entirely — it was the single biggest consumer of vertical
  space on enterprise targets.
- **Fixed misleading Provider line** (`formatter.detect_provider`
  + new `_pick_single_primary` helper). The old format
  `"{gateway} (email gateway, likely delivering to X + Y)"`
  read as ambiguous dual email; the new format promotes ONE
  primary and demotes the rest to `"(secondary)"`. Selection
  rule: Microsoft 365 first (most common enterprise primary),
  then Google Workspace, then list-order fallback. Target
  output: `"Microsoft 365 (primary) via Trend Micro gateway +
  Google Workspace (secondary)"`. The word `(dual)` never
  appears anywhere in provider output — and the v0.9.3 property
  tests assert this.
- **Elevated bare `recon` command**. Running `recon` with no
  arguments no longer dumps the raw Typer help. Instead it
  prints a curated 15-line banner: version + one-line value
  prop, the recommended first command, progressive disclosure
  (`--verbose`, `--full`, `--explain`), three worked examples,
  and a gentle hint about `recon doctor`. Calm, professional,
  no emojis. Subtle cyan accents on the version label and
  section headers.
- **Elevated `recon mcp` startup + shutdown UX**
  (`server._print_mcp_banner`, `server.main`). Running `recon
  mcp` no longer hangs silently. The MCP server now prints a
  professional banner to stderr before handing control to the
  FastMCP loop: version, transport (`stdio`), loaded fingerprint
  and signal counts, a curated list of the top 10 tools with
  one-line descriptions, a config hint pointing at
  `docs/mcp.md`. Ctrl+C produces a clean `"MCP server stopped."`
  line, never a raw `asyncio.CancelledError` traceback.
  `BrokenPipeError` / `ConnectionResetError` are caught as clean
  client-disconnect events. Any other exception is rendered as a
  one-line summary, not a Python scream. The banner goes to
  **stderr** so `stdout` stays clean for the stdio transport's
  JSON-RPC framing.

### Added — Models / storage plumbing

- `SourceResult` gains `cloud_instance`, `tenant_region_sub_scope`,
  `msgraph_host` (all `str | None`, default `None`).
- `TenantInfo` gains `cloud_instance`, `tenant_region_sub_scope`,
  `msgraph_host`, `shared_verification_tokens` (tuple of
  `(token, peer_domain)` pairs — batch-scope only, not cached),
  and `lexical_observations` (tuple of hedged observation
  statements).
- `Signal` gains `positive_when_absent: tuple[str, ...]`.
- `cache.py` round-trips every new field except
  `shared_verification_tokens` — that one is intentionally
  batch-scope-only to prevent a single-domain lookup from
  inheriting peers from a previous batch run.
- New `recon_tool/clustering.py` — `ClusterEntry` frozen
  dataclass + `cluster_tokens` + `compute_shared_tokens` pure
  functions.
- New `recon_tool/lexical.py` — `LexicalObservation` frozen
  dataclass + `classify_subdomains` + `lexical_observations`
  pure functions.
- New `recon_tool/profiles.py` — `Profile` frozen dataclass +
  `load_profile` / `list_profiles` / `reload_profiles` /
  `apply_profile`.

### Changed

- **Fingerprint count: 208 → 227**. Added URIports, DMARC
  Advisor, PowerDMARC, Mimecast DMARC Analyzer, Canvas LMS,
  Blackboard, Moodle, Ellucian Banner, Handshake, Top Hat,
  Dynamics 365 Marketing, Salesforce Marketing Cloud (SFMC),
  Emma, iContact, MailerLite, VMware Cloud, Salesforce NPSP,
  Blackbaud, Classy. Merged TXT-verification detection into
  existing Netlify and WP Engine entries.
- **Signal schema: `positive_when_absent` field added** (opt-in,
  defaults to empty tuple, fully backward compatible with
  pre-v0.9.3 signals.yaml).
- **Default panel layout**: the v0.9.2 bordered Rich Panel with
  80-char width is gone. See UI/X section above. The
  `render_tenant_panel` function signature is unchanged; callers
  still pass its return value to `console.print`.
- **Provider line format**: the v0.9.2
  `"{primary} (primary email via {gateway} gateway)"` format is
  gone. The v0.9.3 format is
  `"{primary} (primary) via {gateway} gateway"`. Same
  information, half the parentheses. When `primary` is inferred
  from non-MX evidence the label becomes `"(likely primary)"`.
- **Gateway-only format**: the v0.9.2 `"{gateway} (email
  gateway)"` is replaced with `"{gateway} gateway (no
  inferable downstream)"` — more explicit about why no primary
  is shown.
- **Insights curation**: the v0.9.2 panel dumped every generated
  insight verbatim. v0.9.3 curates out repetitive laundry lists
  (Security stack, Infrastructure, PKI, Google Workspace
  modules, low-signal org-size hints) that duplicated data
  already visible in the Services block.

### Fixed

- **Provider line ambiguity on dual-DKIM domains.** The old
  `detect_provider` concatenated every likely-primary-email
  provider name with ` + `, producing "Trend Micro gateway
  (likely delivering to Google Workspace + Microsoft 365)" on
  targets where DKIM selectors for both providers existed. The
  new `_pick_single_primary` helper promotes one primary and
  demotes the rest, eliminating the ambiguous "dual" reading.
- **Bare `recon` UX failure**. Running `recon` with no arguments
  used to dump the raw Typer help — ~30 lines of
  machine-generated flag documentation with no value
  proposition, no examples, no suggested first command. Now
  emits a curated banner that tells users what the tool does
  and gives them the exact command to run next.
- **`recon mcp` silent-start failure**. Running `recon mcp`
  used to produce no output at all — just a silent hang on
  stdio. First-time users reported thinking the command had
  crashed. Now prints a professional startup banner to stderr
  with the tool list and config hint, and catches `KeyboardInterrupt`
  cleanly so Ctrl+C produces a `"MCP server stopped."` message
  instead of a raw `asyncio.CancelledError` traceback.
- **Categorized Services double-counting.** In edge cases where
  a service name matched a slug via fingerprint display-name
  lookup AND the raw service name didn't round-trip back
  through the `name_to_slug` map, the categorizer could file
  the same detection under two display names. The new
  lowercase-prefix dedup in pass 2 of `_categorize_services`
  catches both cases.

### Internal

- **Test count**: 1479 passing (1483 total, 4 integration tests
  deselected by default). 123 net new tests across v0.9.3 — 14
  for positive-absence, 30 for lexical, 21 for clustering, 13
  for OIDC enrichment, 25 for profiles, 17 for explanation DAG,
  1 compound test class (TestHardeningObservationIsHedged et
  al.) with ~10 individual tests for the property-based
  hedging harness.
- **Coverage**: 88% package-wide (up from 89% baseline; the
  small dip is because new modules start at high coverage and
  pull the weighted average slightly toward the larger existing
  surfaces). New v0.9.3 modules: `clustering.py` 100%,
  `lexical.py` 98%, `profiles.py` 90%, `absence.py` 100%.
- **Dead code removed**: ~320 lines of v0.9.2 panel body in
  `formatter.py`, plus three unused helper functions
  (`_is_compact_noise`, `_low_scored_service_names`,
  `_annotate_single_source`) that only existed to support the
  old panel. Net formatter change: +~700 lines of new v0.9.3
  layout code minus ~600 lines of deleted old code.
- **Ruff clean**: all checks pass.
- **Pyright clean**: 0 errors, 0 warnings on the package.

### Breaking (for JSON / CLI consumers)

- **Panel output format**. If your tooling parses the default
  `recon <domain>` terminal output (text scraping), it will
  break — the layout is entirely redesigned. Use `--json` for
  programmatic consumers; the `--json` shape is unchanged
  except for the new additive fields (`cloud_instance`,
  `tenant_region_sub_scope`, `msgraph_host`,
  `shared_verification_tokens`, `lexical_observations`, and
  the new `explanation_dag` key under `--explain --json`).
- **Provider string format** in `--json` output follows the new
  `"(primary) via gateway + (secondary)"` convention described
  above. Consumers matching on the exact v0.9.2 string
  `"(primary email via X gateway)"` need to update.

## [0.9.2] — 2026-04-14

This release is a reliability and honesty pass driven by real-world batch
runs across 15 diverse enterprise domains. v0.9.1 was catastrophically
unreliable on CT-heavy targets (27–93% batch failure rate depending on
upstream CT provider state). v0.9.2 raises that to 100% on the same
corpus while surfacing per-source failure reasons so users can see
exactly what went wrong when a lookup is incomplete.

### Breaking (for JSON / signal-name consumers)

- The signal **"Legacy Provider Residue"** has been renamed to
  **"Secondary Email Provider Observed"**. The detection logic and
  `exclude_matches_in_primary` guard are unchanged — only the surface
  name and description differ. Any downstream tool matching on the old
  signal name (in `--json` output's `signals[].name`, in MCP tool
  responses, or in `signals.yaml` overrides) needs to update its
  reference. The rename is described under the Fixed section below.

### Fixed

- **Catastrophic batch timeout rate on CT-heavy domains.** The 60-second
  aggregate resolver timeout cancelled the entire pipeline when crt.sh
  and CertSpotter both exhausted retries, producing 27–93% failure rates
  on enterprise targets depending on upstream CT state. Raised default
  `RESOLVE_TIMEOUT` to 120 seconds and made it configurable via the
  `--timeout` CLI flag.
- **"No information found" hid real errors.** When every source
  transiently failed, the CLI rendered a single generic message with no
  indication of which source failed or why. `ReconLookupError` now
  carries a `source_errors` tuple of `(source_name, reason)` pairs, and
  the CLI renders each one as a dim second line so users can tell
  whether the domain is genuinely empty or whether a transient failure
  hid real data.
- **No source-level retry for transient network failures.** The HTTP
  transport layer retried 429/503 status codes, but timeouts and
  connection resets caused individual sources to return immediately
  with an error — cascading up to a false "no information" verdict on
  domains that would have resolved fine on a retry. A new
  `retry_on_transient` decorator in `recon_tool/retry.py` retries up to
  two times on `httpx.TimeoutException`, `ConnectError`, `ConnectTimeout`,
  `ReadError`, `WriteError`, `RemoteProtocolError`, `asyncio.TimeoutError`,
  and `OSError`, with 0.5s and 1.5s backoff. Applied to `OIDCSource`
  and `GoogleIdentitySource` — the two single-point-of-failure sources
  most sensitive to transient failures. UserRealm and DNS already have
  internal fallback paths.
- **CertSpotter pagination missing.** The provider sent a single GET
  with no `after=` cursor, returning only the first page of issuances.
  Large enterprise domains silently truncated to a fraction of their CT
  footprint, and the caller had no idea the response was partial. Added
  a pagination loop capped at 4 pages (controlled by `_MAX_PAGES`) with
  graceful handling of HTTP 429 — on rate limit, the provider returns
  what's been collected rather than raising.
- **CT provider attribution invisible.** When crt.sh was degraded and
  CertSpotter picked up the fallback, users saw the same generic
  "Some sources unavailable (crt.sh)" note regardless of whether the
  fallback produced 0 or 100 subdomains. New `ct_provider_used` and
  `ct_subdomain_count` fields on `SourceResult` and `TenantInfo` track
  which provider actually contributed, and the panel bottom Note line
  now reads e.g. *"Some sources unavailable (crt.sh) — CT data via
  certspotter (87 subdomains)"*. Plumbed through the disk cache too.
- **"Legacy Provider Residue" mislabeled active dual-use.** On a major
  dev platform owned by a major tech company (M365 primary + Google
  Workspace secondary via DKIM), the signal fired as "Legacy Provider
  Residue: google-workspace". But in that case, both providers are
  actively used — not legacy residue at all. Renamed to **"Secondary
  Email Provider Observed"** with neutral two-sided wording that
  describes the observation without asserting whether it's active dual
  use, migration residue, or a legacy tenant.
- **Provider field silent when MX patterns don't match.** On
  custom/self-hosted email setups, `primary_email_provider` came back
  as `None` and the Provider line said just "Unknown". Rewrote the
  fallback to "Unknown (no known provider pattern matched)" so users
  understand that the tool looked and came up empty rather than
  silently skipping MX analysis.
- **`compute_inference_confidence` missed non-Microsoft corroboration.**
  The corroboration check required `m365_detected`, `display_name`, or
  `auth_type` on a non-OIDC source — fields that only populate for
  Microsoft-side sources. A domain with a tenant_id from OIDC and
  Google Workspace auth confirmation couldn't reach HIGH inference
  confidence because the Google-side fields weren't recognized as
  corroboration. Expanded the check to include `google_auth_type` and
  `tenant_domains` as valid signals.
- **Related-domains list indent regression.** (Carried over from
  v0.9.1 — not a v0.9.2 change, but the bank-run validation exposed a
  latent edge case where the footer line's text was slightly too long
  for the panel, causing Rich to wrap the last word to the panel
  margin. Shortened the footer text.)

### Added

- **`--timeout` CLI flag** — configurable per-lookup aggregate timeout,
  defaults to 120s (was 60s hardcoded). The batch pipeline and every
  resolve path honors the override.
- **`retry_on_transient` decorator** (`recon_tool/retry.py`) — shared
  async retry helper for source-level transient failures. Narrow
  exception list, short backoff, bounded attempts. 12 unit tests
  covering every transient exception class and the non-retry path.
- **CertSpotter pagination loop** — `CertSpotterProvider.query` now
  iterates up to `_MAX_PAGES` pages via the `after=<id>` cursor,
  accumulating subdomains and cert metadata across the full response.
  Stops early on 429, empty page, or missing issuance id.
- **CT provider attribution fields** on `SourceResult` and `TenantInfo`:
  `ct_provider_used` (which CT provider actually succeeded) and
  `ct_subdomain_count` (how many came back after filtering). The count
  is the **filtered** subdomain count — what's left after the wildcard
  removal, noise-prefix skip, and `MAX_SUBDOMAINS` cap in
  `filter_subdomains` — not the raw issuance count returned by the API.
  Surfaced in the JSON output, the disk cache, and the panel bottom
  Note (panel only when degraded sources are also present, so clean
  runs aren't cluttered with reassurance text).
- **`render_source_status_panel()`** in `formatter.py` — compact
  per-source status panel (✓/✗ with brief reason) rendered under
  `--explain` so users can see which sources succeeded and which
  failed without needing `--verbose`. Previously only available in
  the verbose status-line stream during resolution.
- **Partial-success rendering at the merger boundary.** `merge_results`
  already returned a partial `TenantInfo` when `tenant_id` was `None`
  but any source produced services — v0.9.2 tightens the rejection
  path so that when every source returns zero services AND zero
  tenant_id, the raised `ReconLookupError` carries the concrete
  per-source reasons instead of a generic message.
- **18 new tests in `tests/test_retry.py`** covering the retry decorator
  against every supported transient exception class, the non-retry
  semantic-failure path, and instance-method binding.
- **23 new tests in `tests/test_cache_roundtrip.py`** covering every
  `TenantInfo` field including v0.9.1 topology fields and v0.9.2 CT
  provider attribution. Fully exercises the serialize/deserialize
  round-trip and the cache_put/cache_get disk operations in isolated
  temp directories.
- **23 new tests in `tests/test_posture_validation.py`** covering the
  posture rule YAML validator (malformed rules, custom rule loading,
  metadata condition edge cases).
- **21 new tests in `tests/test_formatter_coverage.py`** covering panel
  render edge cases (empty services, degraded + no CT, truncation,
  single-source annotation, M365 classification).
- **30 new tests in `tests/test_cli_coverage_extra.py`** covering
  version and debug callbacks, doctor --fix scaffold, batch
  validation and JSON/CSV modes, exposure/gaps/posture/explain/full/md
  flag combinations, and mutually-exclusive output flag rejection.
- **25 new tests in `tests/test_explanation_coverage.py`** covering
  explanation insight classification branches, `explain_confidence`,
  `explain_observations`, and `serialize_explanation` round-trip.
- **4 new tests in `tests/test_merger_error_surfacing.py`** — R2
  regression guards: source errors carried on the exception, partial
  success when any source produced services, neutral message when
  sources returned empty without errors.
- **13 new tests in `tests/test_cert_providers.py`** covering the
  CertSpotter pagination loop (cursor advance, 429 handling, empty
  pages, missing id, MAX_PAGES cap).
- **1310 total tests** (was 1165 on v0.9.1), 100% passing,
  **88% total coverage** (was 84%), every core logic file ≥80%.

### Changed

- `ReconLookupError` — added `source_errors: tuple[tuple[str, str], ...]`
  field carrying per-source failure reasons. Backward compatible
  (defaults to empty tuple).
- `TenantInfo` — added `ct_provider_used: str | None` and
  `ct_subdomain_count: int` fields. Backward compatible.
- `SourceResult` — added matching `ct_provider_used` and
  `ct_subdomain_count` fields.
- `detect_provider()` in `formatter.py` — when nothing matches, returns
  *"Unknown (no known provider pattern matched)"* instead of the bare
  "Unknown" label, so users know the tool looked and came up empty.
- `compute_inference_confidence()` in `merger.py` — corroboration check
  now accepts `google_auth_type` and `tenant_domains` as valid signals
  in addition to the existing Microsoft-side fields. Raises HIGH
  inference confidence on domains where tenant_id comes from OIDC and
  corroboration comes from Google Identity.
- `OIDCSource.lookup` and `GoogleIdentitySource.lookup` — refactored to
  use a `_fetch` inner coroutine decorated with `retry_on_transient`.
  External API is unchanged (still never raises; always returns a
  `SourceResult`).
- Signal rename in `data/signals.yaml`: "Legacy Provider Residue" →
  "Secondary Email Provider Observed". Logic and `exclude_matches_in_primary`
  guard unchanged; only the surface name and description are different.
  All tests referencing the old name updated.
- `docs/signals.md` and `tests/test_v090_provider.py` updated for the
  rename.
- `render_warning(domain, error=None)` in `formatter.py` — accepts an
  optional `ReconLookupError` argument and renders its `source_errors`
  as dim second lines. All CLI call sites updated.
- Console initialization: `get_console()` now uses `cast(Any, ...)` on
  `sys.stdout` / `sys.stderr` before calling `reconfigure()` so pyright
  accepts the optional-method access pattern while still working
  correctly on Windows where the Python 3.7+ `reconfigure` method
  exists on `_io.TextIOWrapper`.

### Removed

- Nothing. v0.9.2 is purely additive + bug fixes.


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
