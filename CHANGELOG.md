# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.5] - 2026-04-29

**Patch release - multi-client integration assets.** Docs-only change. No
behavior, schema, or fingerprint changes. Adds drop-in install assets so
Claude Code, Kiro, Windsurf, Cursor, and VS Code users can wire up the recon
MCP server and pick up agent guidance without re-deriving it per session.

### Added

- `claude-code/` — full Claude Code plugin scaffold with `.claude-plugin/plugin.json`,
  `.mcp.json` MCP server registration, and a `skills/recon/SKILL.md` skill that
  teaches Claude when and how to use recon in recon's neutral-observation voice.
- `clients/` — copy-pasteable MCP config snippets for Kiro and Windsurf, plus a
  client-by-client install matrix covering Cursor and VS Code + Copilot.
- `AGENTS.md` at repo root — portable agent guidance in the
  [agents.md](https://agents.md) format. Auto-detected by Kiro and other
  agents.md-aware tools; can be referenced from `.windsurfrules`,
  `.cursor/rules/`, or `.github/copilot-instructions.md`.
- `docs/mcp.md` — Kiro added to the per-client config table; PATH gotcha
  expanded to cover all GUI Electron clients.

### Changed

- README links the new `claude-code/` plugin, `clients/` snippets, and
  `AGENTS.md` so users of any supported AI client can find their install path.

## [1.4.4] - 2026-04-27

**Patch release - fingerprint hardening and packaged validator reliability.**
Keeps the public surface stable while tightening broad built-in fingerprint
patterns, making catalog validation work from installed wheels, and grounding
the next roadmap work in validation metrics.

### Added

- Fingerprint match-mode audit reports now include catalog health metrics:
  total fingerprints, detection-rule count, match-mode distribution, metadata
  coverage, and weighted-detection count.
- Roadmap and contributor docs now call out measured fingerprint-library
  priorities, metadata expectations, weak-area notes, and MCP/catalog
  consumption guidance.

### Changed

- Broad Marketo, dmarcian, EasyDMARC, Akamai, AWS ELB, and AWS S3 fingerprint
  substrings were tightened and documented with detection descriptions.
- The 50-domain live validation pass completed with 50 successes, no errors,
  no partial results, no low-confidence results, and only optional `crt.sh`
  degradation observed by `recon doctor`.

### Fixed

- `recon fingerprints check` now uses a packaged validator module instead of
  shelling out to a repo-local `scripts/validate_fingerprint.py` path, so the
  stable command works from installed distributions.

## [1.4.3] - 2026-04-27

**Patch release - validation-driven reliability and local-safety hardening.**
Keeps the public surface stable while bounding long-running MCP state,
tightening local cache paths, and fixing passive DNS/fingerprint edge cases
found during review.

### Changed

- The exposure terminology guard now acts as neutral-copy guidance for
  recon-authored prose, not as a runtime blocklist for domain names, evidence
  strings, or caller phrasing.
- Certificate-transparency ingestion now bounds response processing before
  filtering and sorting, reducing CPU and memory spikes from very large
  provider responses.
- Release workflow OIDC permission tests now pin least-privilege publishing
  scope to the publish job.

### Fixed

- Ephemeral MCP fingerprints now have per-session, per-fingerprint, and total
  detection caps to prevent unbounded process growth.
- CSV batch output now neutralizes spreadsheet formula prefixes in exported
  cells.
- Fingerprint specificity validation now reuses regex safety checks and skips
  specificity evaluation when schema validation already failed.
- Result-cache and CT-cache domain operations now validate and normalize
  domain input before constructing paths, blocking traversal outside cache
  directories.
- Reverse DNS hosting detection now skips non-global A records before issuing
  PTR lookups.
- Subdomain TXT fingerprints now require `subdomain:regex` format, and the
  affected built-in records use explicit subdomain prefixes.

## [1.4.2] — 2026-04-26

**Patch release — doctor status calibration and documentation cleanup.**
Keeps runtime behavior stable while making optional enrichment outages less
alarming and tightening public documentation organization.

### Changed

- `recon doctor` now reports `crt.sh` outages as `WARN` optional enrichment
  degradation instead of a hard `FAIL`. Core source failures still render as
  `FAIL`.
- Documentation is now organized from `docs/README.md`; `docs/roadmap.md` is
  forward-looking and no longer duplicates `CHANGELOG.md`.
- MCP, release, stability, limitations, fingerprint, signal, and weak-area docs
  were refreshed to remove stale counts, stale version wording, and outdated
  command references.

### Removed

- Removed tracked `CLAUDE.md` and added it to `.gitignore`; agent-local guidance
  should stay local instead of shipping in the public repository.

## [1.4.1] — 2026-04-26

**Quality release — sparse-result diagnosis and validation-driven
hardening.** Keeps the public product surface stable while improving how
thin passive evidence is explained, compared, and audited.

### Added

- **Sparse-result diagnosis.** Thin default-panel output now distinguishes
  edge-heavy footprints, custom or self-hosted mail, minimal public DNS, and
  generic sparse public signal cases. The wording remains hedged and points
  users at the passive-only weak-area guidance.
- **Semantic validation comparisons.** Live corpus runs now compare
  per-domain provider, confidence, partial/degraded state, services, slugs,
  and sparse diagnoses. Comparison artifacts classify changes by severity and
  by type (`regression`, `improvement`, `mixed`, `review`, `neutral`).
- **Fingerprint match-mode audit tooling.** New validation helpers audit
  multi-detection fingerprints and classify them as alternate evidence,
  corroborating evidence that needs review, or broad patterns that should be
  tightened before any `match_mode: all` change.

### Changed

- Validation summaries now include sparse-diagnosis rollups so weak-area
  trends are visible across a corpus run.
- Sparse-diagnosis insights are promoted earlier in the default panel so a
  thin run reads as an explained passive result.

### Fixed

- Version metadata fallback and `uv.lock` now track the package version
  consistently.

## [1.4.0] — 2026-04-21

**Hardening release — parser, cache, MCP server coherence, and a
sharper sense of scope.** Targets the three hot paths that real
validation runs have stressed most (malformed upstream responses,
cache round-trips under adversarial inputs, MCP server state
transitions), rebundles the MCP server into the default install,
exposes the fingerprint / signal / profile catalogs as MCP
resources, adds staleness timestamps to every result, and uses the
roadmap to state plainly what recon is — and what it deliberately
leaves to sister tooling.

### Changed

- **MCP is bundled in the default install again.** `pip install
  recon-tool` now installs the `mcp` runtime dependency directly; the
  `recon-tool[mcp]` extra is no longer required. Users who had been
  installing the extra keep working unchanged; users who had avoided
  MCP on purpose can still choose not to run `recon mcp`. No public
  API or CLI surface changed.
- Documentation (`README.md`, `SECURITY.md`, `docs/mcp.md`,
  `docs/security.md`, `docs/stability.md`) updated to reflect the
  bundled-MCP default and the expanded MCP threat model.
- **Fictional-example policy codified and enforced across the tree.**
  The project no longer commits real-company apex domains as examples,
  targets, test corpora, or regression fixtures. Rationale: no upside
  from naming real orgs in a passive-recon tool's public materials;
  accumulating reputational, trademark, and defamation exposure over
  the lifetime of the repository and its forks. See the new
  "Fictional-example policy" section in `CONTRIBUTING.md` for the
  full rule and carve-outs (vendor/product detection names and the
  upstream service hostnames recon itself queries are unaffected).
- **`tests/fixtures/corpus-public.txt` removed.** The 40 real-apex
  corpus previously bundled for `recon fingerprints test <slug>` is
  no longer in-tree. The command now looks for `~/.recon/corpus.txt`
  first, falls back to a new fictional-only `tests/fixtures/
  corpus-example.txt`, and prints a banner when the example file is
  in use so operators know zero matches are expected. Supply your own
  corpus with `--corpus path/to/file` to exercise real detections.
  `docs/performance.md` rewritten to describe methodology without
  naming specific targets.
- **Historical CHANGELOG entries sanitized.** v1.3.0 and v1.2.0
  narrative prose that named specific real apexes has been rewritten
  to describe the behavior in neutral terms. No functional content
  was lost; dated release facts remain intact.
- **`/validation/` gitignore carve-outs.** The directory remains
  ignored for local corpora and result artifacts, with three tracked
  exceptions: `validation/run_corpus.py` (the runner, no company
  names), `validation/corpus-example.txt` (fictional format demo),
  and `validation/README.md` (policy + usage).

### Added

- **MCP resources — `recon://fingerprints`, `recon://signals`,
  `recon://profiles`.** Agents can browse the three catalogs as
  read-only JSON without spending a tool invocation on introspection.
  Each resource is a deterministic projection over the already-loaded
  YAML catalogs (no network calls) — the same data that powers
  `recon fingerprints list` / `recon signals list` / `recon profiles
  list` in the CLI. Changes require `reload_data` to take effect.
- **Staleness timestamps — `resolved_at` and `cached_at` on every
  `TenantInfo`.** `resolved_at` is stamped when live resolution
  produces the result; `cached_at` is populated only by the on-disk
  cache read path. Both flow through the JSON serializer so agents
  can tell at a glance whether they are looking at fresh data or a
  2-minute-old cache hit, and decide whether to re-resolve. Cache
  round-trips preserve `resolved_at` — it reflects when the data was
  first produced, not when the cache entry was last written.
- Reusable live-validation tooling around the existing diverse 50-domain
  corpus. `recon_tool.validation_runner` now summarizes batch JSON,
  compares runs, renders markdown summaries, and
  `validation/run_corpus.py` executes a corpus run through the public
  CLI entrypoint and writes `results.json`, `summary.json`, and
  `summary.md`.
- `docs/roadmap.md` now opens with an explicit "What recon is (and
  what it isn't)" section naming recon as the passive-DNS primitive
  and pointing active scanning, credentialed enrichment, company
  research, and GTM briefing generation at sister tooling. The
  "Intentionally out of scope" list grew accordingly (remote / HTTP
  MCP transport, firmographic enrichment, news / funding / hiring
  feeds, verdicted maturity scores) so external contributors know
  what will be declined up front.

### Fixed

- Hardened malformed-upstream handling for `crt.sh`, CertSpotter, Azure
  metadata, OIDC discovery, and GetUserRealm so invalid or unexpected
  JSON shapes fail explicitly instead of collapsing into generic error
  paths.
- Tightened cache safety and correctness: cache and CT cache now use
  path containment on read/write paths, reject traversal consistently,
  preserve empty `display_name` values on round-trip, and narrow
  filesystem/JSON exception handling.
- Closed MCP server state gaps: cache reload now clears rate-limiter
  state, re-evaluation refreshes cached tenant info, ephemeral
  fingerprint clearing re-merges cached detections, and in-flight tenant
  lookups reserve and release rate-limit slots atomically.
- Reworked fingerprint derived caches into a lock-coherent typed cache
  state so ephemeral inject/clear/reload operations keep detection and
  M365-derived views consistent.

### Validation

- Added regression coverage for malformed upstream bodies, cache
  traversal and round-trip edge cases, server in-flight lookup
  semantics, ephemeral fingerprint cache invalidation, and
  validation-runner summaries.
- Quality gate green on release prep: `pytest tests` (1585 passed, 4
  deselected), `ruff check .`, and `pyright recon_tool tests`.

## [1.3.1] — 2026-04-21

**Security patch — six findings resolved.** External static-analysis
pass surfaced a cluster of low-to-medium issues, mostly reachable only
via local CLI or MCP stdio, but all worth closing. No behavior changes
for legitimate use; each fix tightens a containment boundary that was
previously relying on trust rather than enforcement.

### Fixed

- **Unbounded ephemeral fingerprint injection (MCP DoS)** — Medium.
  ``inject_ephemeral_fingerprint`` had no cap; a long-running MCP
  server could be driven into unbounded memory growth by a
  prompt-injected client calling the tool in a loop. Added a
  ``_MAX_EPHEMERAL_FINGERPRINTS = 100`` cap in
  ``recon_tool.fingerprints``; the MCP tool surfaces capacity
  errors as clean JSON rejections (``EphemeralCapacityError``).
- **Release workflow OIDC scope** — Medium. ``id-token: write`` was
  granted at the workflow level, meaning ``test`` and ``build`` jobs
  (which install and execute dependency code) could mint PyPI
  trusted-publisher tokens. Compromised dependency = publishing
  artifact under our identity. Workflow default is now
  ``contents: read``; each job opts into the scope it actually needs.
  Only ``publish-pypi`` and ``github-release`` request elevated
  permissions.
- **CSV formula injection** — Medium. ``display_name`` originates
  from the attacker-influencable ``FederationBrandName`` response
  and was written verbatim to CSV cells. A value starting with ``=``
  / ``+`` / ``-`` / ``@`` / ``\t`` / ``\r`` would execute as a
  formula when the CSV is opened in a spreadsheet. Added
  ``_csv_safe`` which prefixes unsafe leading characters with a
  single quote; applied to every textual field in
  ``format_tenant_csv_row``.
- **Specificity gate unbounded regex** — Low. ``evaluate_pattern``
  compiled and searched regexes against the synthetic corpus
  without the length cap that ``_validate_regex`` enforces at
  schema-validation time. A pathological regex submitted via PR,
  MCP ephemeral injection, or ``recon fingerprints new`` could
  hang CI or the local wizard. Added a 500-char length guard in
  ``evaluate_pattern`` itself so the gate is safe even when called
  outside the schema validator.
- **Cache clear path traversal** — Low. ``recon cache clear
  <domain>`` forwarded the raw domain to ``cache.cache_clear``
  which built a path directly from it. A crafted argument like
  ``../../.config/settings`` escaped the cache directory and
  unlinked whatever ``.json`` file the user could touch. Added
  ``_safe_cache_path`` using ``Path.is_relative_to`` plus an input
  character guard; traversal attempts now return ``False``
  (nothing deleted) rather than following the path.
- **CT cache ``_safe_path`` prefix-bypass** — Low. The containment
  check used ``str(path).startswith(str(cache_dir.resolve()))`` —
  path-prefix rather than path-aware. A crafted domain like
  ``../ct-cache-malice/evil`` resolved to a sibling directory whose
  path string still matched the prefix. Replaced with
  ``Path.is_relative_to`` and added a character-level input guard.
  Same class of bug as the cache-clear traversal; same fix shape.
- **PTR lookup on private IPs** — Low. ``_detect_hosting_from_a_record``
  unconditionally reverse-resolved the apex A-record IP, including
  RFC1918 / loopback / link-local addresses. A malicious domain
  could publish an A record pointing to an internal IP and the
  tool would ask the operator's resolver for the internal PTR —
  leaking internal DNS names into recon's output. Added
  ``ip.is_private or ip.is_loopback or ip.is_link_local or
  ip.is_reserved or ip.is_multicast`` check before the PTR query.
- **crt.sh unbounded accumulation** — Low. ``filter_subdomains``
  added every matching name into a set, then sorted the full set
  before slicing to ``MAX_SUBDOMAINS``. A domain with a very large
  CT history (tens of thousands of entries) would force the whole
  set into memory and sort it. Added a ``hard_cap = max_count * 10``
  break during accumulation — enough headroom to still prioritize
  high-signal subdomains correctly, bounded enough that no single
  domain can spike CPU.

### Validation

- Full quality gate: ruff check + format clean, pyright 0 errors,
  bandit 0 issues, actionlint clean.
- Pytest: 1550 pass (prior count).
- Each fix is targeted at a reported finding; none of them change
  observable behavior for legitimate input (no CHANGELOG entries
  needed in user-facing docs beyond this one).

## [1.3.0] — 2026-04-21

**Portfolio discovery in batch mode.** When ``recon batch`` resolves
multiple domains, the JSON output now surfaces two new correlation
signals: cryptographically-strong tenant-ID sharing (same M365
customer account) and hedged display-name overlap (same brand after
normalization). Uses data already collected — zero new network
calls, zero new sources.

### Added

- **Tenant-ID clustering (``shared_tenant``)**: When 2+ domains in a
  batch share the same Microsoft 365 tenant ID, each domain's JSON
  entry carries a ``shared_tenant`` list naming the other peers.
  Cryptographically strong — same tenant ID = same M365 customer
  account. Not hedged; this is provable via OIDC discovery. Three
  sibling apexes belonging to the same corporate group collapse to a
  shared peer set in the batch output.
- **Display-name clustering (``shared_display_name``)**: When 2+
  domains' tenant display names normalize to the same key,
  each entry carries a ``shared_display_name`` list with the raw
  display names (for audit), the normalized key, and the peer
  domains. Conservative match — exact normalized equality only
  (``Acme Corp`` + ``Acme Corp.`` cluster; ``Acme`` + ``Acme Holdings``
  do not). Normalization strips one trailing corporate suffix
  (``inc`` / ``llc`` / ``gmbh`` / etc.) and collapses whitespace /
  punctuation.
- ``recon_tool.clustering.compute_tenant_clusters`` and
  ``compute_display_name_clusters`` — pure functions exposed for
  the MCP server and external consumers who want to run the
  clustering on their own ``TenantInfo`` lists. 11 new unit tests
  covering the tenant / display-name paths.

### Use case

Portfolio discovery on a candidate domain list. An IT reseller or
M&A analyst runs ``recon batch portfolio.txt --json`` and the output
names which apexes belong to the same corporate group, without any
additional lookups. Pairs well with the existing
``shared_verification_tokens`` clustering for a three-tiered signal:

- **Tenant-ID match** — provable, same customer account.
- **Display-name match** — hedged, same brand text.
- **Verification-token match** — hedged, same operator-scoped
  credential.

The JSON fields are independent — a pair can appear in one, two, or
all three. Downstream consumers rank them however they like.

### Validation

- Portfolio smoke test on a three-apex group sharing a single M365
  tenant and display name: all three fields populate correctly with
  symmetric peer lists.
- Full test suite: 1550 pass (1539 + 11 new clustering tests).
- Static gate: ruff + format + pyright + bandit + actionlint all
  clean.

## [1.2.1] — 2026-04-21

**Security patch.** The MCP ``inject_ephemeral_fingerprint`` tool
validated schema but bypassed the v1.2 specificity gate. A caller
could inject a pattern like ``cname:\.com$`` and poison every
subsequent lookup in that session with false positives. Blast radius
was small (in-memory, per-session, could not persist), but the gate
is cheap and worth enforcing everywhere the catalog accepts input.

### Fixed

- ``inject_ephemeral_fingerprint`` now runs every detection pattern
  through ``recon_tool.specificity.evaluate_pattern`` and rejects the
  injection with a clear diagnostic when any pattern exceeds the 1%
  synthetic-corpus match threshold. Same gate as
  ``recon fingerprints check`` and ``recon fingerprints new``, so
  the three ingress paths are now consistent.

### Validation

- Expanded validation sweep against a 31-domain weak-area corpus
  (heavy-Cloudflare, higher-ed, Chinese/APAC, regulated verticals,
  EU fintech, self-hosted, IDN). All 31 resolve without error;
  sparse results on thin-signal domains are honest, not empty.
- Security audit pass on userrealm.py (defusedxml + xml_escape both
  confirmed in use), the ``recon fingerprints check`` subprocess
  path (list form, sys.executable, no shell), and the MCP rate
  limiter (monotonic clock, soft cap, no bypass via table-flood).
  No other findings.

## [1.2.0] — 2026-04-21

**Contribution trust.** v1.1 gave contributors the plumbing; v1.2 adds
the guards that make contributions *safe to merge*. A
pattern-specificity gate rejects over-broad regexes before review; a
scaffolding wizard runs every check before emitting YAML; a test
command resolves a new fingerprint against a public domain corpus so
contributors can see what it actually matches. No engine changes, no
new detections — the point is that the next wave of detections
(community or solo) can't accidentally poison the catalog.

### Added

- **Pattern-specificity gate** (`recon_tool/specificity.py`). Every
  detection regex is now matched against a synthetic adversarial
  corpus of ~1500 strings spanning TXT / SPF / MX / CNAME / NS. If a
  pattern matches more than 1% of the corpus, `recon fingerprints
  check` rejects it as over-broad. The threshold is calibrated so all
  227 built-in entries pass, while a deliberately-broad pattern like
  `cname:\.com$` fails with a clear diagnostic. Off by default with
  `--skip-specificity` for debugging; on by default for PRs and CI.
- **`recon fingerprints new <slug>`** — scaffolding wizard. Prompts
  for name, category, detection type, pattern, optional description
  and reference. Runs three guards before emitting YAML: (1) slug
  uniqueness against the built-in catalog, (2) schema validity,
  (3) specificity. Prints a paste-ready entry or writes to a file
  via `--output`.
- **`recon fingerprints test <slug>`** — runs one fingerprint against
  a domain corpus and reports which match. Contributors point at their
  own corpus with `--corpus path/to/file` or drop a list at
  `~/.recon/corpus.txt`. Helps answer "is my regex too loose or too
  tight" without hand-resolving DNS.
- **`tests/fixtures/corpus-example.txt`** — fictional-company example
  corpus showing the expected file format. Real-company corpora are
  never committed; see CONTRIBUTING.md for the rationale. (Note:
  earlier point releases bundled a public-companies corpus; it was
  removed in v1.4.0.)
- **`docs/weak-areas.md`** — honest list of deployment shapes where
  recon looks sparse by design (heavy-CDN orgs, Chinese / APAC tech
  stacks, regulated verticals behind web proxies, fully self-hosted
  shops, parked / portfolio apexes). Names what the sparse result
  actually means and what to do instead of over-interpreting it.
  Linked from limitations.md.
- **`docs/performance.md`** — published batch wall-clock and memory
  numbers (50 / 100 / 500 domains), methodology for reproducing,
  per-step time budget. Stops users from guessing where the latency
  goes.

### Changed

- **`scripts/validate_fingerprint.py`** — now runs the specificity
  gate on every pattern in addition to the runtime schema check and
  cross-file duplicate-slug check. `--skip-specificity` opts out
  when debugging.
- **CONTRIBUTING.md** — fingerprint PR section updated for the new
  `fingerprints new` / `test` / `check` workflow. New "engine changes
  go through a design doc" heads-up before the signals section —
  fingerprints are data and can iterate freely; signal / fusion /
  absence engines are inference code and bad changes affect every
  domain recon analyses.

### Deferred to post-1.2

- **Bulk fingerprint additions.** Each QA round during v1.2 planning
  suggested 20-100 new fingerprints, mostly based on pattern-matching
  `<vendor>-domain-verification=` by analogy. Spot-checks showed
  most of those patterns don't exist — the SaaS in question uses
  account-based verification or API-key auth rather than DNS.
  Catalog growth is welcome but each entry needs vendor-doc
  verification, which is proper v1.2+ work. The infrastructure in
  this release makes each new entry a small PR going forward.

**Contribution-ready.** The fingerprint catalog is now one file per
category, new CLI inspect commands let contributors audit the data
without opening YAML, and CI gained an `actionlint` gate so the kind
of unresolvable-action-ref regression that broke the first v1.0.2 tag
can't reach `main` again. No user-visible detection or output changes
in this release — this is infrastructure for everything that comes
next.

### Added

- **Per-category fingerprint layout** — ``recon_tool/data/fingerprints.yaml``
  (one 60KB file, 235 entries, 8 duplicate slugs) is now
  ``recon_tool/data/fingerprints/`` (8 per-category files, 227 unique
  slugs, zero duplicates). The eight files:
  - ``ai.yaml`` — AI / LLM providers, agent frameworks.
  - ``email.yaml`` — email platforms, gateways, DMARC / DKIM tooling.
  - ``security.yaml`` — EDR, SIEM, IdP, zero-trust, credential hygiene.
  - ``infrastructure.yaml`` — cloud, CDN, DNS, CAs, CI/CD.
  - ``productivity.yaml`` — suites, helpdesk, HR, knowledge.
  - ``crm-marketing.yaml`` — CRM, sales intel, ad platforms.
  - ``data-analytics.yaml`` — warehouses, BI, observability.
  - ``verticals.yaml`` — education, nonprofit, payments, misc.
  The loader globs ``data/fingerprints/*.yaml`` in sorted order; custom
  ``~/.recon/fingerprints.yaml`` still works as a single file and a
  new ``~/.recon/fingerprints/`` directory is also accepted for users
  who want per-category organization of their overrides. Slug order
  after load is deterministic and identical to the monolith except
  for the 8 duplicates, which are now collapsed into single entries
  with their detection rules merged.
- **``recon fingerprints list`` / ``show`` / ``check``** — contributor
  and user inspection commands for the fingerprint catalog.
  - ``list`` supports ``--category`` substring and ``--type`` exact
    filters, plus ``--json`` for scripting.
  - ``show`` renders the full definition (detection rules, patterns,
    descriptions, references) for a single slug. Synthetic slugs
    (``exchange-onprem``, ``self-hosted-mail``) that are emitted by
    source-layer probes rather than loaded from YAML are documented
    here too — users who see those slugs in their output can always
    find provenance without grepping code.
  - ``check`` validates the catalog against the runtime schema and
    surfaces cross-file duplicate slugs. Wraps
    ``scripts/validate_fingerprint.py`` with sane defaults.
- **``recon signals list`` / ``show``** — same pattern for the signal
  catalog. ``show`` surfaces candidates, metadata conditions,
  contradictions, requires-signals chains, expected-counterparts,
  and positive-when-absent lists — everything the absence and
  two-pass evaluators look at.
- **``actionlint`` in pre-commit and CI.** Catches unresolved action
  refs, bad shell in ``run:`` blocks, and deprecated expressions at
  commit time and in a dedicated ``workflow-lint`` CI job. The
  v1.0.2 release regressed because ``astral-sh/setup-uv@v8`` isn't a
  real floating tag; ``actionlint`` catches that class of error
  locally and in CI. Pinned to ``actionlint@v1.7.12``.
- **``scripts/split_fingerprints.py``** — the one-shot migration
  script that produced the split, kept in the repo for audit. A
  reviewer can re-run it against the pre-split monolith to verify
  the split is reproducible.

### Changed

- **``scripts/validate_fingerprint.py`` now accepts a directory** and
  pools slugs across files for a cross-file duplicate-slug check.
  Single-file invocation is unchanged — directories are an additive
  capability for the split-catalog layout.

### Docs

- **CONTRIBUTING.md** updated for the split-catalog layout —
  "find the right file" step added, PR template checklist swapped to
  the new ``recon fingerprints check`` command, fingerprint-add
  recipe now shows ``recon fingerprints show <slug>`` as the
  post-add verification step.
- **CLAUDE.md** reflects 227-fingerprint count (down from 235) and
  the new ``data/fingerprints/`` directory layout.

### Process guards

The first v1.0.2 tag push failed because ``astral-sh/setup-uv@v8``
isn't a published floating tag — only ``v8.0.0`` and ``v8.1.0`` exist.
Two guards now prevent that class of regression:

1. ``actionlint`` runs in pre-commit on every commit touching
   ``.github/workflows/``.
2. ``actionlint`` runs as the first job in CI so PRs with unresolved
   action refs fail at the workflow-lint stage, before any Python
   work executes.

Before future tag pushes, verify each bumped action ref exists with
``gh api repos/<owner>/<repo>/git/refs/tags/<ref>`` — especially for
actions that don't publish floating majors.

## [1.0.2] — 2026-04-20

**Polish pass.** Toolchain current, test suite pyright-clean, dead code
removed, seven bug fixes surfaced by CLI edge-path audits, provider
attribution improved for self-hosted mail, "we looked and found nothing"
now returns a sparse result instead of an error. Validated against
450 domains across eight corpora (international banking, pharma,
mining, telecom, logistics, government agencies, UN / NGO bodies, EDU /
state gov, DTC startups, plus a 50-domain diverse-industry sweep
covering big tech, automotive, luxury, fast food, Chinese giants,
aerospace, and retail) with zero errors and zero regressions.

### Added

- **Python 3.13** added to the CI test matrix and the package
  classifiers. Supported runtimes are now 3.10 / 3.11 / 3.12 / 3.13.
- **Dependabot** configured for GitHub Actions and Python dependencies
  with weekly cadence and patch/minor grouping.
- **README badges** — CI status, PyPI version, supported Python
  versions, license.
- **CI pyright scope now covers `tests/`** so type-annotation drift
  can't re-accumulate the way it did (652 errors pre-polish → 0 now).

### Changed

- **Email security score is now an inventory, not a grade.** The
  score line went from `Email security 3/5 good (DMARC reject, DKIM,
  SPF strict)` → `Email security 3/5: DMARC reject, DKIM, SPF strict`
  → `Email security: DMARC reject, DKIM, SPF strict`. The verdict
  adjectives (`weak` / `basic` / `moderate` / `good` / `strong` /
  `excellent`) came out first — we see apex DNS, not the full posture,
  so a graded assertion is more than the tool can honestly make. The
  `N/5` fraction came out next: even without the adjective, `3/5` was
  read as "mediocre" and the controls aren't equally weighted anyway
  (DMARC `reject` is load-bearing, BIMI is decorative). The machine-
  readable `email_security_score` field stays in `--json` for
  consumers that genuinely need to sort or filter. The same `/5`
  stripping now extends to `--posture` and `--exposure` panels and
  to `compare_postures` assessment summaries so the format stays
  consistent everywhere.
- **Provider attribution no longer over-credits on-prem Exchange.**
  Large orgs with self-operated mail infrastructure used to fall
  through to `Exchange Server (on-prem / hybrid)` as the primary
  provider whenever `owa.<apex>` / `autodiscover.<apex>` resolved,
  even when the public MX clearly routed through their own
  operator-owned mail hostnames. A synthetic `self-hosted-mail`
  slug now fires when MX records exist and none of them match a
  recognized cloud provider or gateway fingerprint, and that slug is
  recognized as a primary email provider in the topology computation.
  The Exchange on-prem detection still fires as a secondary service
  signal in the same output, so the hybrid-identity reality of these
  orgs is still visible — it's just no longer promoted to the
  Provider line. Roughly a third of the diverse 50-domain validation
  corpus got more accurate Provider lines as a result, most of them
  large industrial and APAC orgs running self-operated mail.
- **DKIM inference behind commercial gateway.** When MX points to a
  commercial email gateway (Proofpoint, Mimecast, Cisco IronPort,
  Barracuda, Trend Micro, Trellix, Symantec) AND DMARC is enforcing
  (`quarantine` or `reject`), the score now credits DKIM with the
  annotation `DKIM (inferred via Proofpoint)` (etc.). Fortune-500
  orgs with enforcing DMARC almost always DO sign with DKIM — just at
  custom selectors the tool can't enumerate. Without this inference
  the apex score penalized orgs for a control they effectively have.
  The inference chain is visible in the score string so the user can
  audit it.
- **`partial=True` semantic tightened.** The JSON `partial` flag now
  fires only when a core source (OIDC, UserRealm, Google Identity,
  DNS) is degraded — not when a CT provider (crt.sh, CertSpotter) is
  degraded. CT pipelines are chronically flaky and the code handles
  their degradation gracefully via fallback + cache, so they shouldn't
  flip the global `partial` bit. The per-source status is still
  surfaced in the `degraded_sources` list for consumers who want the
  detail.
- **GitHub Actions bumped to current majors** — `checkout v4 → v6`,
  `setup-python v5 → v6`, `setup-node v4 → v6`, `upload-artifact v4 →
  v7`, `download-artifact v4 → v8`, `setup-uv v5 → v8`,
  `action-gh-release v2 → v3`. Node 20 deprecation warnings are now
  gone; `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` workaround removed since
  all pinned actions target Node 24 natively.
- **"All sources empty, no errors" returns a sparse `TenantInfo`**
  instead of raising `ReconLookupError`. "We looked and found nothing"
  is a valid observation, not a failure. Previously, a domain with
  no detectable patterns would get a hard error in single-domain
  lookups and an `error` entry in batch output; now both paths emit
  a clean result with `provider = "Unknown (no known provider
  pattern matched)"`. Raising is reserved for the case where every
  source actually failed.

### Removed

- **Three more narrative-judgment signals** in the same class as
  Shadow IT Risk / Complex Migration Window / Governance Sprawl
  (retired in v1.0.1). None were observation — they stitched two
  observable facts into a critique that only DNS can't actually make.
  - `Security Stack Without Governance` — "security investment may
    lack email-layer controls" is opinion; the two underlying
    observations (security tools + DMARC not enforcing) are already
    visible on their own lines.
  - `AI Adoption Without Governance` — inferred "shadow AI
    deployment" from absence of specific IDPs; speculative.
  - `DevSecOps Investment Without Email Governance` — inferred that
    engineering security investment "hasn't extended to email";
    pure narrative.
- **Dead code in `sources/dns.py`** — `_safe_resolve_sync` and
  `_set_resolver` had no callers (including tests). The sync resolver
  helper was for a testing pattern that's no longer in use; the
  resolver override was never wired up.

### Docs

- **`docs/roadmap.md` trimmed from 631 → 207 lines.** The historical
  per-release detail now points to CHANGELOG.md (source of truth);
  the post-1.0 ethos and "intentionally out of scope" sections kept
  but tightened. Invariants and priority order stay front and center.
  Added a concrete v1.1 target describing the planned split of
  `fingerprints.yaml` into per-category files — design sketch, scope
  breakdown, non-goals, and the reason it waits for v1.1 (coherent
  with the community-contribution pipeline).
- **`docs/signals.md` trimmed from 130 → 74 lines.** Large
  auto-generated signal table removed (signals.yaml itself is the
  source of truth and shorter). Design rules section added listing
  retired signals and the invariant each violated, so contributors
  can see why something wouldn't be accepted before proposing it.
- **`docs/fingerprints.md` tightened.** Detection-types table kept.
  Added a concrete "Testing a new fingerprint" recipe. Email security
  score table updated for the gateway-inferred DKIM path. Removed
  implementation-detail notes about enrichment tiers that belonged in
  code comments, not user docs.

### Fixed

- **Test suite pyright-clean.** 652 errors → 0. `tests/` execution
  environment relaxes `reportPrivateUsage` (tests legitimately
  white-box private APIs) and parameter-type rules (pytest fixtures
  inject by name), but keeps structural checks on. Fixture generators
  get proper `Iterator[T]` return types; test assertions now
  null-guard before calling `re.match`; unused destructured variables
  are prefixed with `_`.
- **`recon cache clear` now actually clears everything for a domain.**
  Previously it only cleared the CT subdomain cache at
  `~/.recon/ct-cache/`; the TenantInfo result cache at
  `~/.recon/cache/` was left untouched and silently served stale
  JSON on subsequent runs. This surfaced during validation — after
  updating recon, a cached TenantInfo result kept showing retired
  signals like "AI Adoption Without Governance" even after a
  `cache clear <apex>`. The command now clears both caches and
  reports each count separately; `cache_clear` / `cache_clear_all`
  helpers added to `cache.py`.
- **`recon doctor` no longer emits empty error messages.** Many
  `httpx` exception classes (`ReadTimeout`, `ConnectTimeout`) raise
  with an empty message string, so `str(exc)` rendered as
  `FAIL  crt.sh (cert transparency) — ` with nothing after the em-
  dash. A module-level `_fmt_exc(exc)` helper falls back to
  `type(exc).__name__` when the message is empty; applied
  everywhere in `cli.py` that previously did `render_error(str(exc))`
  on a catch-all `Exception`.
- **Wildcard-DNS guard on Exchange-on-prem detection.** Domains that
  point `*.<apex>` at a single IP (so every subdomain resolves to
  the same address) used to trigger every probed prefix in
  `_detect_exchange_onprem` and get mislabelled as running Exchange
  Server. The detector now probes a nonsense prefix and bails when
  it also resolves — an unambiguous wildcard signature.
- **IDN / Punycode domains accepted.** The validator regex anchored
  the TLD at `[a-z]{2,}`, which rejected every `xn--`-prefixed TLD
  (e.g. `xn--p1ai` for Russian, `xn--fiqs8s` for Chinese). The
  pattern now allows letters, digits, and internal hyphens in the
  TLD (letter-first, alphanumeric-last, min two chars) so IDN
  domains are accepted while numeric and hyphen-bracketed TLDs
  still reject.
- **`--profile` no longer a no-op without `--posture`.** Profile
  lenses only apply to posture observations, so running
  `recon <domain> --profile fintech` without a posture-enabling
  flag silently produced identical output to `recon <domain>`.
  Passing `--profile` now auto-enables posture rendering.
- **Hardening Controls panel renders colored check marks.** The
  `--exposure` panel built its ✓/✗ line with f-string Rich markup
  (`[green]✓[/green]`) appended to a `Text` object. `Text.append`
  does not parse markup, so those tags rendered as literal text.
  Style is now passed via the `style=` kwarg.

### Refactor

- **Test file names de-versioned.** Fourteen test files named after
  the QA round or release when they were written (e.g.
  `test_v090_absence.py`, `test_v093_clustering.py`) renamed to
  their subject matter (`test_absence_engine.py`,
  `test_clustering.py`, etc.) via `git mv` so history is preserved.
  Docstring leading lines also stripped of the `v0.9.x — QA Round
  N:` preamble. Post-1.0 the version of introduction is no longer
  meaningful context for where tests live.

## [1.0.1] — 2026-04-20

**Accuracy & reliability pass** driven by a 150-domain validation sweep
across large, mid-size, and regional targets in multiple regions and
industries. All fixes stayed inside the project invariants
(passive-only, zero credentials, no engine expansion, hedged output).

### Fixed

- **`autodiscover.<apex>` no longer false-positives `exchange-onprem`
  on Microsoft 365 cloud tenants.** The detector queried type A and
  relied on dnspython returning empty when the name was a CNAME to
  `autodiscover.outlook.com`. dnspython chases CNAMEs on type-A
  queries, so M365 domains were flagging as on-prem. The detector now
  queries CNAME first for `autodiscover` and suppresses when the
  immediate target is in the M365 cloud zone
  (`*.outlook.com` / `*.office.com` / `*.cloud.microsoft` /
  `*.mail.protection.outlook.com` / `*.office365.com`). Genuine
  hybrid Exchange (CNAME to org-owned infra, or direct A) still
  fires. Other prefixes (`owa`, `outlook`, `exchange`, `mail-ex`,
  `webmail`) keep the A-or-CNAME path — those names are on-prem-only
  when they resolve. See `sources/dns.py::_detect_exchange_onprem`,
  regression tests in `test_dns_subdetectors.py::TestExchangeOnpremAutodiscover`.

- **`GoogleIdentitySource` no longer claims "Managed" Workspace on
  every domain.** The `_is_workspace_domain` heuristic searched the
  `accounts.google.com/ServiceLogin` response body for the `hd=`
  parameter and the word `"identifier"`. Both are always present in
  Google's sign-in page (the URL parameter is echoed verbatim into
  the body, and the page is an identifier-capture form), so the
  check returned `True` for every queryable domain — including
  fabricated ones. The body heuristic is removed. Managed Workspace
  customers are still detected via the DNS fingerprint path (MX
  `aspmx.l.google.com`, SPF `_spf.google.com`, DKIM
  `google._domainkey`, GWS module CNAMEs to `ghs.googlehosted.com`).
  A federated IdP redirect still triggers the `Federated` detection.
  This removes the cascade of phantom "Dual Email Provider",
  "Google-Native Identity", and "Google Cloud Investment" insights
  from M365-primary targets.

- **`cisco-identity` TXT no longer mis-attributed as the SSO IdP.**
  The slug fires on the `cisco-ci-domain-verification=` TXT token,
  used by many Cisco products (Duo, Customer Identity, Secure Email,
  Intersight) — not specifically the org's SSO IdP. Removed from
  `_IDP_SLUG_MAP` in `insights.py`; the federated-auth insight now
  correctly falls back to the generic `ADFS/Okta/Ping` line when
  no dedicated IdP evidence is present. The slug still emits the
  `Cisco (Identity)` service fact.

- **12% of big-enterprise lookups timed out at the 120s aggregate
  budget — now 0%.** Root cause: when CertSpotter rate-limited with
  HTTP 429, `_RetryTransport` slept **30s × 3 retries = 90s** per
  query while CertSpotter's own application code already handled 429
  by breaking the pagination loop. HTTP-layer retry was fighting
  application-layer handling and burning the aggregate budget.
  `http_client(retry_transient=False)` is a new flag that skips
  `_RetryTransport`; CertSpotter opts in. Page-level
  `@retry_on_transient` on `_fetch_page` also removed for the same
  reason (3 × 8s = ~25s of accumulated delay on slow-CT targets).
  Single-domain lookup time on the worst-case targets went from 120s
  (timeout) to 2-12s.

### Changed

- **`CertSpotter _MAX_PAGES` 4 → 2, `_CT_TIMEOUT` 8 → 6,
  `MAX_RELATED_ENRICHMENTS` 25 → 15.** Budget tightening to reduce
  per-domain fan-out under batch concurrency. Two CertSpotter pages
  still cover ~500 certs, and the enrichment cap is prioritised so
  high-signal subdomain prefixes (auth, login, sso, api, …) survive.

### Removed

- **`Shadow IT Risk` signal.** Framed sanctioned enterprise SaaS
  (Canva / Mailchimp / Airtable) as "shadow IT risk" at any scale.
  Violated the "observable facts in neutral language" invariant and
  misread the common-case consumer-brand SaaS footprint of a large
  org as a defect.
- **`Complex Migration Window` signal.** Narrative synthesis on top
  of "security stack + dual-provider email" observations. The tool
  can observe the two inputs; it cannot observe that a migration is
  in progress. Violated the "no timeline narrative generation"
  invariant.
- **`Governance Sprawl` signal.** Depended on `Shadow IT Risk`.
- **`expected_counterparts` on `AI Adoption` and
  `Agentic AI Infrastructure`.** Produced "Missing Counterparts"
  absence insights like `AI Adoption — Missing Counterparts: Lakera,
  Okta, CyberArk, Beyond Identity` on nearly every AI-adopting
  target. The listed slugs were vendor recommendations, not
  observable co-occurrence relationships — their absence does not
  constitute a defect observable from DNS. The
  `expected_counterparts` mechanism itself remains available for
  user-customised signals in `~/.recon/signals.yaml`; no built-in
  signal currently uses it.

### Note on exit codes

Sparse-evidence domains (zero slugs, zero services, no provider pattern
matched) previously raised `ReconLookupError` in the CLI path, printed
"No information found for {domain}", and exited with code 3
(`EXIT_NO_DATA`). They now render a clean `Unknown` panel and exit 0.

- Scripting consumers that relied on exit code 3 as "no data found"
  must switch to checking the JSON output's `provider` field for
  `"Unknown (no known provider pattern matched)"` or the empty
  `services` / `slugs` lists.
- Exit code 3 still fires when the resolver genuinely can't get a
  clean result from *any* source (all sources errored). That's rare.
- Exit code 4 (`EXIT_INTERNAL`) is unchanged.

### Note on upgrade

- `google_auth_type` is now `None` more often: the source only
  populates it on a genuine federated redirect. Any consumer that
  depended on the previous "Managed" default on every domain was
  consuming a bogus signal — switch to the DNS-backed
  `primary_email_provider` / slug set instead.
- Consumers relying on `Shadow IT Risk`, `Complex Migration Window`,
  or `Governance Sprawl` in the signals output will no longer see
  those names. No replacement — the underlying observations (consumer
  SaaS slugs, dual-provider detection, security stack) are still
  present in the slug/service set.

## [1.0.0] — 2026-04-17

**Stability commitment.** recon is now 1.0. From this release forward,
all surfaces tagged **stable** in `docs/stability.md` will not break
between patch or minor releases. Breaking changes require a major
version bump and a deprecation window.

### Added

- **`docs/security.md`** — engineering-level threat model. Trust
  boundaries, attack surface, mitigations with file:line refs
  (validator.py domain regex, http.py SSRF protections, fingerprints.py
  ReDoS heuristic, ct_cache.py path-traversal guard), known limitations
  (DNS rebinding with sub-second TTLs), out-of-scope.
- **`docs/limitations.md`** — honest inventory. What recon can't see
  (Copilot/Gemini, heavily proxied domains, internal services,
  network-level facts), what it underclaims on (bundled AI, dormant
  dual-provider, sovereignty when OIDC is silent), known noise
  patterns, when to reach for something else.
- **`docs/schema.md`** — JSON output contract. ~45 stable fields
  documented with types, nullability, allowed values. Nested object
  shapes for `cert_summary` and `bimi_identity`. Experimental fields
  (`slug_confidences`) separately tagged.
- **`tests/test_json_schema_contract.py`** — conformance tests that
  assert every stable field is present and correctly typed on both
  rich and sparse fixtures.
- **`scripts/release.py`** — semi-automated release flow. Clean-tree
  check, version-bump consistency, CHANGELOG entry check, quality gate
  (ruff + pyright + pytest + coverage), git commit + tag, confirm-to-push.
  `--dry-run` flag for testing.
- **`docs/release-process.md`** — full release documentation. Human
  half (`scripts/release.py`), automated half (GH Actions), pre-release
  checklist, hotfix workflow, yanking a broken release, SemVer
  commitment, Python support policy.

### Changed

- **`docs/stability.md`** — fully expanded. Full CLI flag table, all 17
  MCP tools (stable), full list of stable JSON fields, CLI exit codes,
  YAML schema commitments, Python support policy (CPython N-2 = 3.10,
  3.11, 3.12).
- **JSON output — always-present fields.** `detection_scores`,
  `cert_summary`, and `bimi_identity` are now always present in
  `--json` output (null when unavailable) rather than conditionally
  emitted. Backward compatible for consumers that check
  `field is not None`; slight breaking change for consumers that
  relied on `field in payload` as a presence check. This was a
  schema-conformance fix for 1.0.
- **Dev Status classifier** — `pyproject.toml` updated from
  `Development Status :: 4 - Beta` to
  `Development Status :: 5 - Production/Stable`.

### Roadmap

- All v1.0 deliverables shipped. `docs/roadmap.md` updated accordingly.
- Post-1.0 ideas (NetworkX graph, portfolio detection, temporal CT
  evidence, feedback-driven posterior tuning) remain in the roadmap as
  non-commitments.

## [0.11.0] — 2026-04-17

Community & confidence. The biggest build yet. Three themes:
(1) `--confidence-mode strict` drops hedging qualifiers when evidence
is dense. (2) Community fingerprint pipeline enables outside
contributions without drowning in bad YAML. (3) Bayesian fusion
(experimental) replaces the three-bucket detection-score threshold
with a principled per-slug posterior.

### Added

- **`--confidence-mode {hedged,strict}`** CLI flag. Default `hedged`
  (unchanged). `strict` drops hedging qualifiers ("observed",
  "likely", "indicators") on dense-evidence targets (High confidence
  + 3+ corroborating sources). Sparse-data output is never touched —
  the "never overclaim when evidence is thin" invariant stays
  load-bearing. New module `recon_tool/strict_mode.py`.
- **Community fingerprint pipeline.**
  - `scripts/validate_fingerprint.py` — local validator that runs the
    same checks recon uses at runtime (regex safety, required fields,
    detection types, weight range, `match_mode`). Exits 0/1 with
    per-entry error messages.
  - `CONTRIBUTING.md` — new fingerprint submission section with
    validate command, chained-pattern guidance, PR checklist.
  - `.github/ISSUE_TEMPLATE/fingerprint_request.md` — structured
    template for requesting new fingerprints.
  - `.github/PULL_REQUEST_TEMPLATE/fingerprint.md` — structured
    template for fingerprint PRs.
  - `.github/workflows/ci.yml` — new `validate-fingerprints` job that
    runs on every PR.
- **Bayesian fusion (experimental).** New module `recon_tool/fusion.py`.
  Pure-Python Beta conjugate update. Per-source priors ranked by
  informational content (OIDC > DKIM > MX > TXT > A/CNAME). Opt-in
  via `--fusion`. Emits `slug_confidences` tuple on TenantInfo and
  in `--json` output. Tagged **experimental** — algorithm and field
  shape may evolve.
- **`docs/stability.md`** — stability policy for 1.0. Lists stable
  vs experimental surfaces. Documents what "stable" means
  (backward-compat guarantee between patch and minor releases).

### Changed

- No behavior change by default. Strict mode, fusion, and the
  community pipeline are all opt-in or additive.

## [0.10.3] — 2026-04-17

MCP agent ergonomics. The server now self-documents so AI clients
call tools correctly without prompt babysitting. All changes stay
inside the local-stdio-only invariant — no HTTP transport, no
hosted mode, no server mode.

### Added

- **Rich Server Instructions.** FastMCP is now initialized with a
  3400-character instructions block that injects a user manual
  into the model's context every session. Covers: when to use
  which tool, composition patterns (`lookup_tenant` → `analyze_posture`
  → `simulate_hardening`), the passive-only invariant, confidence
  semantics, and when to use `explain=True`.
- **`recon doctor --mcp`** flag. Validates the MCP server setup:
  mcp package installed, server module imports cleanly, Server
  Instructions present, tools enumerate, `recon` on PATH. Emits
  copy-pasteable JSON config for Claude Desktop, Cursor, VS Code +
  Copilot, and Windsurf.
- **Windsurf config** documented in `docs/mcp.md`
  (`~/.codeium/windsurf/mcp_config.json`).
- **PATH gotcha note** for GUI MCP clients (Claude Desktop,
  Windsurf) that don't inherit the shell PATH. Includes the
  `python -m recon_tool.server` fallback pattern.

### Changed

- No behavior change in the MCP tools themselves. Just better
  agent ergonomics on top of the existing surface.

## [0.10.2] — 2026-04-17

Passive coverage depth. Three targeted expansions to detection
coverage and run-over-run intelligence, all staying inside the
passive / zero-creds / per-domain-storage invariants.

### Added

- **Medium-tier subdomain enrichment.** New `medium_subdomain_lookup`
  in `sources/dns.py` adds MX + DKIM probing on top of the lightweight
  CNAME + TXT tier for the highest-signal subdomain prefixes (`auth`,
  `sso`, `login`, `idp`, `api`, `mail`). Catches SaaS and email tenants
  that publish verification records on subdomains distinct from the
  apex. Capped at 6 subdomains per lookup to stay within the DNS budget.
- **`recon delta <domain>`** CLI command. Reads the previous cached
  `TenantInfo` from `~/.recon/cache/`, runs a fresh lookup, diffs
  services / slugs / auth / DMARC / confidence / email-security-score,
  and updates the cache with the new snapshot. No manual export file
  required. The existing `--compare previous.json` flag still works
  for explicit baselines.
- **Chained fingerprint pattern documentation.** Added a `match_mode: all`
  section to `docs/fingerprints.md` explaining how to require multiple
  detections (across record types) before a fingerprint fires.
  Infrastructure has been in place since earlier versions; now documented
  for contributors.

### Changed

- **Resolver enrichment pipeline.** `_enrich_from_related` now splits
  capped subdomains into medium-tier (top-signal prefixes, MX + DKIM)
  and lightweight (everything else, CNAME + TXT only). Separate domains
  continue to get the full DNS lookup.

### Roadmap

- Added **v0.10.3 — MCP agent ergonomics** (Server Instructions, tool
  docstring polish, `recon doctor --mcp`).

## [0.10.1] — 2026-04-16

Provider accuracy + UX depth. Follow-up to v0.10 that addresses
structural detection issues exposed during real-world validation:
SSO hub mislabeling, DKIM undercount on Fortune 500 targets,
service miscategorization, and the "everyone has both providers"
noise problem.

### Added

- **Generic DKIM selector probing.** dns.py now probes `s2`,
  `dkim`, `mail`, `k2` as TXT records on top of the existing
  Exchange (`selector1`/`selector2`), Google (`google`), and ESP
  selectors. Large enterprises using non-standard selectors now
  get DKIM credit on the email security score instead of
  "No DKIM selectors observed" false negatives.
- **`email_confirmed_slugs` parameter** in `detect_provider()`.
  Filters slug-based secondary providers to only those with MX
  or DKIM evidence — dormant account registrations no longer
  clutter the Provider line.

### Changed

- **SSO hub label.** `federated-sso-hub` slug display changed
  from "Shibboleth / SAML SSO hub" to "SSO hub". A DNS A record
  at `sso.domain.com` can't distinguish Entra ID from Okta from
  Shibboleth — the previous label overstated what the tool
  knows. Okta and ADFS specific detections (via `okta.*` /
  `adfs.*` subdomains) keep their specific labels.
- **Service categories rethink.**
  - `"Other"` renamed to `"Business Apps"` across
    `_SERVICE_CATEGORIES_ORDER`, `_CATEGORY_BY_SLUG`, and
    `_categorize_service()`.
  - Microsoft Teams, XMPP/Jabber, Slack → Collaboration (was
    Business Apps / Other).
  - Intune / MDM → Identity (was Business Apps / Other).
- **Gateway + DKIM → confirmed primary.** `_compute_email_topology`
  now promotes gateway+DKIM evidence to `primary_email_provider`
  (confirmed) instead of `likely_primary_email_provider`
  (inferred). DKIM proves the provider signs mail for this
  domain — that's not inference, it's confirmation. Weaker non-MX
  evidence (TXT, OIDC, UserRealm) still sets `likely_primary`.
- **Provider-line secondaries filtered.** Dormant account
  detections (M365 tenant exists but no DKIM or MX evidence) no
  longer show as "(secondary)" in the default Provider line.
  They still appear in `--full` and `--json` output.

### Example diffs

Softchoice before: `Provider     Exchange Server (on-prem / hybrid) behind Trend Micro gateway + Microsoft 365 (account detected) + Google Workspace (account detected)`

Softchoice after: `Provider     Microsoft 365 (primary) via Trend Micro gateway + Google Workspace (secondary)` — M365 confirmed via DKIM, GWS confirmed via DKIM too.

Stripe before: `Provider     Google Workspace (primary) + Microsoft 365 (secondary)`

Stripe after: `Provider     Google Workspace (primary)` — M365 tenant exists but has no MX/DKIM evidence, so it's not shown in the default Provider line.

## [0.10.0] — 2026-04-16

CT resilience + UX overhaul. Two themes: (1) when live CT providers
both fail, a per-domain cache serves as fallback; (2) the default
panel output is now tight enough for a CEO glance — zero redundancy
between header, services, and insights.

### Added

- **Per-domain CT cache.** New `recon_tool/ct_cache.py` stores CT
  provider results as JSON files in `~/.recon/ct-cache/{domain}.json`.
  Seven-day default TTL, one file per domain, no aggregated store.
  Successful provider queries automatically populate the cache.
- **CT cache fallback.** When both crt.sh and CertSpotter are
  degraded, the fallback chain now checks the per-domain CT cache
  before returning an empty subdomain set. The panel shows "CT: from
  local cache, N days old" so users know they're seeing cached data.
- **Cache CLI commands.**
  - `recon cache show [domain]` — inspect cache state for a domain
    or list all cached domains with subdomain counts and age.
  - `recon cache clear [domain]` — remove cache for a specific domain.
  - `recon cache clear --all` — remove all cached CT data.
- **Cache age in panel output.** When CT data comes from cache, the
  Note section shows "CT: from local cache, N days old (M subdomains)"
  in info tone (not warning) so it reads as a recovery event, not an
  error.
- **`ct_cache_age_days` field** in JSON output — `null` when data
  comes from a live provider, integer when from cache.

### Changed

- **`_detect_cert_intel()` now caches on success.** Every successful
  CT provider query writes to the per-domain cache, so future
  degraded runs have fresh fallback data.
- **Degraded-source rendering** updated to distinguish live fallback
  ("CT fallback: crt.sh → certspotter") from cache fallback ("CT:
  from local cache, 3 days old").
- **UX overhaul — insight curation.** Aggressive dedup: 18
  restatement prefixes dropped (insights that just re-list services
  already visible in the categorized block). Default mode caps at 5
  insights + email score; `--full` shows all. Vague labels like
  "Complex Migration Window" and "Governance Sprawl" cut entirely.
- **UX — Email row cleanup.** Protocol config (DKIM, DMARC, SPF,
  MTA-STS, BIMI, TLS-RPT, Exchange Autodiscover) removed from the
  default Email services row — the email security score insight
  already covers these. Provider-line services (M365, Google
  Workspace, gateway) also stripped from Email to eliminate
  duplication. `--full` still shows everything.
- **UX — no decorative color.** Section headers changed from
  `bold cyan` to `bold`. Color reserved for functional meaning
  (green=high confidence, yellow=warning) per modern CLI norms.
- **UX — CT note suppressed.** Routine "CT fallback: crt.sh →
  certspotter" notes suppressed in default output — infrastructure
  plumbing that added noise on nearly every run. Cache fallback
  and actual warnings still surface.
- **Provider accuracy.** When Exchange Autodiscover AND an M365
  tenant are both detected, the Provider line now reads "Microsoft
  365 via [gateway]" instead of "Exchange Server (on-prem / hybrid)".
  On-prem only leads when no M365 tenant is found (e.g. vatican.va).
- **Bundled AI inference.** M365 presence → "Microsoft Copilot
  (likely)" in Services > AI. Google Workspace → "Google Gemini
  (likely)". Hedged with "(likely)" to distinguish from DNS-
  confirmed detections like Anthropic.

## [0.9.4] — 2026-04-16

Infrastructure-only release. No feature changes. Toolchain and release
hygiene to make the 1.0 stability commitment credible.

### Added

- **`SECURITY.md`** — vulnerability reporting policy at the repo root
  (GitHub's standard location). Separate from the `docs/security.md`
  threat model planned for 1.0.
- **Pre-commit hooks** — `.pre-commit-config.yaml` with Ruff (lint +
  format) and Pyright. Prevents bad code from reaching CI.
- **`pip-audit` in CI** — dependency vulnerability scanning runs on
  every PR and every release build.
- **Coverage gate** — CI now fails if test coverage drops below 80%.
  Current coverage: 87%.
- **`uv.lock`** — reproducible builds via uv lockfile. Development
  workflow uses `uv sync --extra dev`; end-user install instructions
  (`pip install recon-tool`) are unchanged.

### Changed

- **MCP packaging changed in this release.** At the time, `pip install
  recon-tool` no longer pulled in the MCP dependency tree. Current
  releases ship the MCP server in the default install; see the README
  for up-to-date packaging guidance.
- **CI migrated from pip to uv.** Both `ci.yml` and `release.yml` now
  use `astral-sh/setup-uv@v5` for faster, reproducible installs.
- **Trusted Publisher on PyPI** — release pipeline already uses
  OIDC-based publishing via `pypa/gh-action-pypi-publish`; no static
  API tokens.

### Developer notes

- `pip install -e ".[dev]"` still works but `uv sync --extra dev` is
  now the recommended development workflow.
- Pre-commit can be activated with `pre-commit install` after cloning.
- `pip-audit` is included in the `[dev]` extra for local use.

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
  references with RFC-2606 reserved `example.com` / `example.org`.
  Repo is now clean of real company names outside of fingerprint
  detection targets and the Contoso/Northwind/Fabrikam fictional-
  example convention.
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
