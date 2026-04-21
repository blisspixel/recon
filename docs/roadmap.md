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

## Post-1.0 ideas (not commitments)

Any of these could turn into a minor release. None are blocking.
Each has to stay below the "bulletproof over bloat" bar — if it
compromises correctness, reliability, or the invariants, it doesn't
ship.

- **CT-organization search.** Use `crt.sh`'s subject `O=` field to
  find related certs issued to the same organization. Portfolio
  discovery signal; prototype post-1.0.
- **Tenant display-name clustering across batch.** If `balcan.com`
  has tenant display name "Balcan Innovations Inc." and
  `balcaninnovations.com` matches that substring, they're almost
  certainly the same entity. Uses data we already collect.
- **BIMI VMC legal-name clustering.** Strictly-verified legal names
  in BIMI VMCs are the strongest passive signal for corporate
  ownership clustering. Low false-positive rate, low coverage.
- **Counterfactual hardening simulation.** Valuable for red-team and
  M&A due diligence. Read-only on cached evidence.
- **Temporal evidence from CT metadata.** Use `not_before` /
  `not_after` to surface "legacy configuration residue".
- **Feedback-driven posterior tuning.** Opt-in local
  `~/.recon/feedback/` files that downweight specific
  source/fingerprint combinations flagged as false positives. Never
  leaves the machine.
- **Wayback Machine historical snapshots.** Zero-creds public API
  returns historical URLs for a domain; a passive temporal
  enrichment.
- **Chained-pattern fingerprint reference set.** `match_mode: all`
  infrastructure shipped in v0.10.2 but few built-in fingerprints
  use it. A curated set of 20–30 chained examples would give
  contributors concrete patterns to model from.
- **Bayesian evidence fusion.** Per-source reliability priors +
  Beta conjugate update for per-slug confidence. Output a
  `slug_confidences` field, tagged experimental.

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
