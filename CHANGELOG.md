# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- `CLAUDE.md` for Claude Code project context.
- `.kiro/steering/recon-project.md` for Kiro IDE context.
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
