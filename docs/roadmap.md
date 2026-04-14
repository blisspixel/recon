# Roadmap

Constraints: passive, zero-creds, no paid APIs, no local database. Priority: correctness → explainability → composability → accuracy → new features. Shipped work is in [CHANGELOG.md](../CHANGELOG.md).

## Now

Make sparse output on locked-down / heavily proxied targets actually useful, without adding data sources or violating constraints.

## Soon

Top 6 only, ordered by impact × effort. Every item is passive, zero-creds, and improves either sparse-target insight or explainability.

1. **Hedged hardened-target recognition**
   - *Files:* `data/signals.yaml`, `absence.py`, `signals.py` (add `positive_when_absent` to Signal schema).
   - *Change:* Generalize the absence engine so signals can express positive observations when an edge-proxy composite is present and expected consumer SaaS is absent.
   - *Done when:* `--explain` on a known hardened domain emits a hedged positive observation instead of only "missing counterpart" gaps.

2. **CT SAN feedback loop on sparse targets**
   - *Files:* `resolver.py`, `sources/cert_providers.py`.
   - *Change:* When an edge-hardening composite fires, raise `MAX_RELATED_ENRICHMENTS` ~50% and extend `HIGH_SIGNAL_PREFIXES` (`sso`, `portal`, `secure`, `idp`, `auth`, `login`). No new detection type — discovered SANs reuse the existing cname/txt pipeline.
   - *Done when:* Known hardened test domains surface 2–3× more related subdomains under `--full`.

3. **CT subdomain lexical taxonomy**
   - *Files:* new `lexical.py` (or extend `insights.py`), `signals.yaml`.
   - *Change:* Prefix/suffix parser on CT-discovered subdomains (`dev-`, `stg-`, `prd-`, `eu-west-`, `us-east-`). Emit hedged signals ("Mature DevOps Pipeline", "Geo-Distributed Infrastructure"). Pure analysis, no network.
   - *Done when:* Lexical signals appear on domains with rich CT data.

4. **Site-verification token clustering in batch mode**
   - *Files:* batch pipeline, `models.py`.
   - *Change:* In-memory map of `google-site-verification` tokens across a batch run. No persistence. Shared tokens surface as likely subsidiary/parent relationships.
   - *Done when:* `recon batch domains.txt --json` includes a `shared_verification_tokens` array on matching domains.

5. **Identity federation branding extraction**
   - *Files:* `sources/microsoft.py`, `models.py`, `insights.py`.
   - *Change:* Pull branding asset URLs (logo paths, CDN hosts) from the Microsoft OIDC tenant discovery response already being fetched. Surface as optional metadata; feeds acquisition/parent-company inference.
   - *Done when:* Tenants with custom branding show the branding host in JSON output.

6. **Custom profile templates + interpretive lenses**
   - *Files:* new `profiles/` loader, `posture.py`, CLI.
   - *Change:* YAML files in `~/.recon/profiles/` that reweight or filter signals. CLI flag `--profile fintech`. Works via MCP `analyze_posture` too.
   - *Done when:* Loading a profile changes which signals are emitted or how they're weighted in `--posture` and MCP `analyze_posture` output, with zero changes to `data/signals.yaml`.

## Later / maybe

- Dynamic agent-driven weight tuning (MCP ephemeral fingerprints already cover most of this).
- Cloud strategy inference from CA families + infrastructure CNAMEs.
- Temporal signal sequencing from CT timestamps.
- Delegation graph topology in chain mode.
- Docker image for CI/air-gapped use.

## Intentionally not doing

**Hard no — violates core constraints.** Any active scanning or probing (ports, brute-force, zone transfers, web scraping, TLS handshakes, HTTP probing of target infrastructure). Paid APIs. Credentialed access. Local databases or history stores. Bundled ASN/GeoIP data.

**Not this tool.** HTML output, web dashboard, `recon serve`, interactive REPL, plugin system, STIX2/Maltego exports, Pydantic models, Prometheus metrics, SBOM/signed releases, JSONL streaming, locked JSON schema contract, llms.txt, A2A cards. recon is a CLI + MCP server; pipe `--json` into whatever format you need.

**Design choices that stay.** No confident "maturity" or "zero-trust" verdicts on sparse data — the same evidence fits deliberate hardening or a dormant/parked/small-shop domain, so positive observations stay hedged and two-sided. No offensive guidance or takeover hints — observable facts in neutral language only. No generic subdomain name-pattern matching (`n8n.*`, `automation.*`) — too noisy; verification TXT and CNAME delegations are more reliable. No timeline narrative generation — delta mode surfaces raw changes; synthesis is the user's or agent's job.
