# Roadmap

Shipped work lives in [CHANGELOG.md](../CHANGELOG.md). This file is
forward-looking: invariants, post-1.0 ethos, ideas worth prototyping,
and what's deliberately out of scope.

## Invariants (non-negotiable)

- **Passive only.** No active scanning, port probes, zone transfers, or
  TLS handshakes against the target.
- **Zero credentials, zero API keys, zero paid APIs.** Every data source
  reachable without an account.
- **No bundled ML models, embeddings, or ASN/GeoIP data.**
- **No aggregated local database.** Per-domain JSON in `~/.recon/` is
  fine; a shared sqlite/duckdb store is not.
- **Hedged output only.** Overclaim on sparse data is worse than
  mumble; mumble on strong data is worse than hedge. The
  `--confidence-mode strict` flag drops hedging when evidence density
  is genuinely high.

Anything new must fit inside this box.

## Priority order

Correctness → reliability → explainability → composability → new features.
Post-1.0 this gets stricter: hardening what exists beats adding new
surface. See the Post-1.0 ethos section below.

## Shipped releases

| Release | Shipped | Theme |
|---------|---------|-------|
| v0.9.4  | 2026-04-16 | Toolchain & release hygiene (CI, pre-commit, MCP optional extra) |
| v0.10   | 2026-04-16 | CT resilience + UX overhaul |
| v0.10.1 | 2026-04-16 | Provider accuracy, DKIM expansion, category rethink |
| v0.10.2 | 2026-04-17 | Passive coverage depth, chained fingerprints, delta mode |
| v0.10.3 | 2026-04-17 | MCP agent ergonomics |
| v0.11   | 2026-04-17 | Community fingerprints + `--confidence-mode strict` |
| v1.0.0  | 2026-04-17 | Stability commitment |
| v1.0.1  | 2026-04-20 | Accuracy + reliability from 150-domain validation |
| v1.0.2  | 2026-04-20 | Polish — observation-not-verdict, gateway-inferred DKIM, CI bumps |
| v1.1.0  | 2026-04-21 | Contribution-ready — per-category YAML split, inspect CLI, actionlint gate |
| v1.2.0  | 2026-04-21 | Contribution trust — specificity gate, `fingerprints new`/`test`, weak-areas + perf docs |

See `CHANGELOG.md` for per-release detail.

## Post-1.0 ethos: bulletproof over bloat

At 1.0 the public surface is frozen. Post-1.0 effort prefers
*hardening what exists* over *adding what's new*:

- Tighter fingerprints (fewer false positives, more chained patterns)
  beat new slugs.
- Better evidence for existing claims beats new inference types.
- Deeper test coverage on sparse / adversarial inputs beats higher
  target counts.
- Cleaner code in hot paths beats new code paths.

**Data-file expansion is NOT bloat.** The YAML files
(`fingerprints.yaml`, `signals.yaml`, `profiles/*.yaml`) are data, not
code. Schema is stable, validation runs on PR, engine behavior doesn't
change. Community contributions land here.

The thing to avoid is growing the *engine* (new CLI commands, new
output formats, new subsystems, new config surfaces). Engine stays
lean; data grows.

## Shipped in v1.1: per-category fingerprint catalog

The monolithic `recon_tool/data/fingerprints.yaml` (235 entries, 8
duplicate slugs) is now `recon_tool/data/fingerprints/{ai,email,
security,infrastructure,productivity,crm-marketing,data-analytics,
verticals}.yaml` (227 unique slugs). The loader globs the directory
in sorted order; custom `~/.recon/fingerprints.yaml` still works as a
single file and a new `~/.recon/fingerprints/` directory is also
accepted. Contributors inspect the catalog with `recon fingerprints
list` / `search` / `show` and validate candidate files with `recon
fingerprints check`. `signals.yaml` and `posture.yaml` stay single
files — they're smaller and more interdependent.

## v1.2 targets — detection quality and contributor trust

**Theme.** v1.1 shipped the *plumbing* for external contributions. v1.2
is the first release where the plumbing has to prove it was worth
shipping: tighter built-in detections, validator guards that catch
semantic problems (not just syntax), UX that makes sparse results
honest, and docs that set accurate expectations for what recon does
and doesn't find.

**Scope (six items, each with an acceptance test):**

1. **Chained-pattern fingerprint reference set.** Curate 20–30
   high-confidence vendors using `match_mode: all` (e.g. Datadog,
   Snowflake, Figma, Notion, Linear, Asana). The `match_mode: all`
   infrastructure shipped in v0.10.2 but few built-in fingerprints
   use it. The reference set both reduces existing false positives
   and gives contributors concrete patterns to model from.
   *Acceptance:* ≥20 chained entries merged; each has a regression
   test domain in the validation corpus.

2. **`recon fingerprints test <slug>`.** Run one fingerprint (built-in
   or candidate) against the validation corpus and print which
   domains match. Lets contributors test a pattern before PRing and
   lets maintainers triage reported false positives without editing
   test files.
   *Acceptance:* Command exists; ships with a bundled 50-domain
   corpus covering the major detection classes.

3. **Pattern-specificity gate in the validator.** Fail
   `recon fingerprints check` when a regex matches a suspicious
   share of a synthetic-domain corpus — catches the class of
   "valid YAML, would match 30% of the internet" that the current
   schema validator can't see.
   *Acceptance:* A deliberately-broad regex (`cname:\.com$`) is
   rejected; real existing fingerprints all pass.

4. **Sparse-result UX + `docs/weak-areas.md`.** When recon resolves
   to few services, the output should *actionably* say so ("domain
   is heavily Cloudflare-proxied — passive signals are thin; try
   `recon chain` or check related apexes") instead of looking like a
   bad run. Pair with a `docs/weak-areas.md` naming the categories
   recon is honest about being thin on: heavy-Cloudflare orgs,
   China-region tech stacks, regulated verticals behind web proxies,
   fully self-hosted shops.
   *Acceptance:* A run against a known-sparse target produces output
   the user can reason from; the weak-areas doc exists and is linked
   from README + limitations.

5. **Batch performance numbers.** One real published table:
   50 / 100 / 500 domains, wall-clock and memory. Goes in
   `docs/performance.md` or similar. Stops users from guessing.
   *Acceptance:* Table committed, reproducible via a scripted run.

6. **CONTRIBUTING signal-engine caveat.** Fingerprint PRs are
   welcome; changes to the signal / fusion / absence engines need
   a one-page design doc first. Closes the "solo-maintained
   inference logic" gap that no amount of contributor docs fixes
   by itself.
   *Acceptance:* CONTRIBUTING updated with the design-doc template
   link.

**Explicitly NOT in v1.2:**

- Ballooning the fingerprint count to 1000+. Quality > count. Growth
  is welcome but gated by the specificity check above.
- Paid-API or credentialed integrations (VirusTotal, Censys paid,
  passive-DNS services). Violates the zero-creds invariant.
- Active scanning, plugin runtimes, bundled ML. Hard no.
- File splits for `formatter.py` / `server.py` / `cli.py`. Still
  "only when a feature forces it."

**"We shouldn't have done this" signals for v1.2 itself:**

- If the specificity gate trips on more than a handful of existing
  fingerprints, it's too strict — recalibrate.
- If the chained-pattern set takes more than 2 weeks of solo work,
  we're over-engineering — ship what's ready, defer the rest.
- If no external PR has landed by the v1.2 ship date *despite* both
  the v1.1 plumbing and the v1.2 quality gates being in place, pause
  on contributor-facing work and talk to users instead.

## Ideas worth prototyping (not commitments)

Any of these could turn into a minor release. None are blocking.
Each has to stay below the "bulletproof over bloat" bar — if it
compromises correctness, reliability, or the invariants, it doesn't
ship.

- **CT-organization search.** Use `crt.sh`'s subject `O=` field to
  find related certs issued to the same organization. Portfolio
  discovery signal; adds a new network surface — let v1.1 settle
  first.
- **Tenant display-name clustering across batch.** If `balcan.com`
  has tenant display name "Balcan Innovations Inc." and
  `balcaninnovations.com` matches that substring, they're almost
  certainly the same entity. Uses data we already collect — no new
  network surface. Good first post-v1.1 feature candidate.
- **BIMI VMC legal-name clustering.** Strictly-verified legal names
  in BIMI VMCs are the strongest passive signal for corporate
  ownership clustering. Low false-positive rate, low coverage.
- **Counterfactual hardening simulation.** Valuable for red-team and
  M&A due diligence. Read-only on cached evidence. Large feature —
  needs demand evidence before scoping.
- **Temporal evidence from CT metadata.** Use `not_before` /
  `not_after` to surface "legacy configuration residue".
- **Feedback-driven posterior tuning.** Opt-in local
  `~/.recon/feedback/` files that downweight specific
  source/fingerprint combinations flagged as false positives. Never
  leaves the machine.
- **Wayback Machine historical snapshots.** Zero-creds public API
  returns historical URLs for a domain; a passive temporal
  enrichment.
- **Bayesian evidence fusion refinements.** Experimental flag landed
  in v0.11; refine per-source reliability priors based on
  accumulated validation feedback.

## Opportunistic refactoring

Three files carry disproportionate maintenance burden:
`formatter.py` (2,600 lines), `server.py` (1,900 lines), `cli.py`
(1,200 lines). Splitting them is the right move *when* a feature
change forces the split; not as a standalone milestone.

## Intentionally out of scope

**Hard no.** Active scanning. Paid APIs. Credentialed access.
Bundled ML / embedding weights. Aggregated local databases. Bundled
ASN / GeoIP data. A plugin system that runs user code.

**Not this tool.** HTML output, web dashboard, TUI, `recon serve`,
interactive REPL, scheduled/daemon mode, STIX2 / Maltego / MISP
exports, Prometheus metrics, Homebrew tap, Docker image, PDF
reports. recon is a CLI plus a local-stdio MCP server; `--json` is
the integration surface. Want a rendered graph? Pipe node-link
JSON into Mermaid. Want PDF reports? Pipe `--md` into pandoc. Want
SIEM ingestion? Pipe `--json` into your SIEM.

**Design choices that stay.**

- No confident "maturity" or "zero-trust" verdicts on sparse data.
  Positive observations stay hedged.
- No offensive guidance or takeover hints. Observable facts in
  neutral language only.
- No generic subdomain service-name matching (`n8n.*`,
  `grafana.*`). Too noisy; verification TXT and CNAME delegation
  are more reliable.
- No timeline narrative generation. Delta mode surfaces raw
  changes; synthesizing them into a story is the user's job.
- No confident acquisition / ownership verdicts from shared tokens
  or branding. Hedged "possible relationship (observed)" only.
- No posture / insights layer triggers a new network call.
  Synthesis runs on cached evidence.
