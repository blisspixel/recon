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
| v1.2.1  | 2026-04-21 | Security patch — specificity gate wired into MCP `inject_ephemeral_fingerprint` |
| v1.3.0  | 2026-04-21 | Portfolio discovery — batch-mode tenant-ID + display-name clustering |
| v1.3.1  | 2026-04-21 | Security patch — 6 static-analysis findings resolved |
| v1.4.0  | 2026-04-21 | Hardening — parser/cache/MCP coherence, live-validation tooling, MCP bundled by default |

See `CHANGELOG.md` for per-release detail.

Main-branch work since v1.4.0 stays in the same lane: rerun the
50-company validation corpus with `validation/run_corpus.py`, feed
findings back into tighter detections, and keep the product surface
stable. New decisions should come from live validation output, not
from widening scope.

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

## Next: post-v1.4

v1.4.0 is the current release. The shipped releases table and
`CHANGELOG.md` cover what landed; this section is the active
forward lane. No commitment on ordering or ship date — new work
comes from live validation findings, not scope expansion.

### Live-validation lane (always on)

- Re-run the diverse 50-domain corpus on networked machines with
  `validation/run_corpus.py` and keep comparison artifacts when
  regressions appear.
- Use live findings to tighten existing detections and trim false
  positives and false negatives before adding any new surface.
- Keep hardening MCP, cache, and server hot paths when real defects
  are found, especially under adversarial local-agent inputs.

### Detection work

- **`match_mode: all` coverage audit.** The chained-pattern
  infrastructure shipped in v0.10.2 and the specificity gate in
  v1.2.0; the open question is how many built-in fingerprints
  actually use chained patterns. Audit the catalog, identify
  high-value vendors still on single-pattern matches (Datadog,
  Snowflake, Figma, Notion, Linear, Asana, and similar), and
  convert the ones where evidence supports it. Each conversion
  needs a regression domain in the validation corpus.
- **Sparse-result CLI polish.** `docs/weak-areas.md` exists but a
  thin run doesn't yet point users at it. When the resolver returns
  few services, the panel should name the likely reason (heavy
  Cloudflare, minimal DNS, self-hosted) and link the doc — so a
  sparse result reads as a diagnosed answer, not a bad run.

### Doc polish backlog

Small, additive, no engine change. Good single-PR sweep when time allows:

- `docs/limitations.md`: add an APAC / China domestic-stack row;
  enumerate known DKIM selector blind spots.
- `docs/weak-areas.md`: add "wildcard-heavy DNS zones" as a named
  weak area.
- `docs/security.md`: name the ReDoS heuristic classes we guard
  against; state explicitly that ephemeral fingerprints are
  memory-only and never touch disk; acknowledge the
  sub-second-TTL DNS-rebinding limitation as accepted.
- `docs/schema.md`: concrete `added_services` / `removed_services`
  example in the Delta section.
- `docs/mcp.md`: tighten the `autoApprove` warning banner; add a
  "Network calls?" column to the tools table; add a second
  ephemeral-fingerprint example using `match_mode: all`.
- `docs/fingerprints.md`: short "false positives we've killed"
  subsection (unanchored regexes, dormant TXT, wildcard A) so new
  contributors see the failure modes before they recreate them.
- `docs/signals.md`: one custom-signal worked example.

## Ideas worth prototyping (not commitments)

Any of these could turn into a minor release. None are blocking.
Each has to stay below the "bulletproof over bloat" bar — if it
compromises correctness, reliability, or the invariants, it doesn't
ship.

- **CT-organization search.** Use `crt.sh`'s subject `O=` field to
  find related certs issued to the same organization. Portfolio
  discovery signal; adds a new network surface, so weigh the
  reliability cost against the clustering value before scoping.
- **BIMI VMC legal-name clustering.** Strictly-verified legal names
  in BIMI VMCs are the strongest passive signal for corporate
  ownership clustering. Low false-positive rate, low coverage.
  Natural follow-on to the tenant display-name clustering that
  shipped in v1.3.0.
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

## What recon is (and what it isn't)

recon is the **passive-DNS primitive**. One job: take an apex, return
hedged observations about the tech stack and identity posture using
only public DNS, certificate transparency, and unauthenticated
identity-discovery endpoints. It's designed to be the layer that
other tools — active scanners, company-research enrichers, GTM
pipelines — *consume*, not the layer that does those jobs itself.

Active scanning, credentialed enrichment, company research, news /
funding / hiring signals, organisational graph discovery, and any
kind of "structured AI briefing" synthesis live in sister tooling
(e.g. primr). recon stays narrow on purpose so those tools have a
solid, honest, passive foundation to build on. Humility over
completeness — the features recon doesn't ship are usually the ones
that would quietly make its hedging less trustworthy.

## Intentionally out of scope

**Hard no.** Active scanning. Paid APIs. Credentialed access.
Bundled ML / embedding weights. Aggregated local databases. Bundled
ASN / GeoIP data. A plugin system that runs user code. Remote / HTTP
MCP transport (local stdio only; if you want a shared team service,
that's a different tool wrapping recon, not recon itself).

**Not this tool.** Company research, firmographic enrichment, news /
funding / hiring feeds, GTM briefing generation, contact data,
verdicted "maturity scores". HTML output, web dashboard, TUI,
`recon serve`, interactive REPL, scheduled/daemon mode, STIX2 /
Maltego / MISP exports, Prometheus metrics, Homebrew tap, Docker
image, PDF reports. recon is a CLI plus a local-stdio MCP server;
`--json` is the integration surface. Want a rendered graph? Pipe
node-link JSON into Mermaid. Want PDF reports? Pipe `--md` into
pandoc. Want SIEM ingestion? Pipe `--json` into your SIEM. Want
company research? That's a separate tool's job.

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
