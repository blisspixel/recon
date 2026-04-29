# AGENTS.md — recon

This file is portable agent guidance in the [agents.md](https://agents.md) format. AI coding tools that auto-detect `AGENTS.md` (Kiro, OpenAI Codex, Jules, Aider, others) load it automatically. Tools that don't (Claude Code, Cursor, Windsurf) can reference or include it from their own rules / skill files.

If you are an AI agent reading this in a recon-aware project: this is how to use the recon CLI and MCP server well.

## What recon is

Passive domain intelligence. Given an apex domain, recon returns hedged observations about an organization's public technology stack and identity posture using public DNS, certificate transparency, and unauthenticated identity-discovery endpoints. No credentials, no API keys, no active probing.

## When to reach for recon

Use recon when the user wants to understand a domain's public-facing configuration:

- "Is `acme.com` on Microsoft 365? What's their tenant ID?"
- "Score the email security on `northwindtraders.com`."
- "What SaaS vendors does `fabrikam.com` appear to use?"
- "Find related domains for `contoso.com`."
- "Compare the posture of `a.com` and `b.com`."

Do not use recon for:

- Active scanning, port scans, or credentialed inventory.
- Vulnerability assessment or exploit checks.
- Company financials, news, hiring signals, or firmographic data.
- Anything that would require touching the target's own servers beyond reading their published DNS records and the standards-compliant `mta-sts.{domain}` endpoint.

If the user wants a verdict like "is this company secure," recon is not that tool. It surfaces observations; the user supplies the judgment.

## Before first invocation

Confirm recon is installed before the first call in a session:

```bash
recon --version
```

If the command is not found:

> "`recon-tool` is not installed. It's a Python CLI from github.com/blisspixel/recon that reads public DNS, identity endpoints, and certificate transparency — no credentials needed. Install with `pip install recon-tool`? (Python 3.10+ required.)"

Wait for explicit approval, then `pip install recon-tool` followed by `recon doctor` to verify connectivity. If `recon --version` succeeds, continue immediately.

## Two invocation modes

### Default mode — panel output

Use this when the user asks recon-shaped questions conversationally — "recon contoso.com", "what does pokemon.com run on" — without explicitly requesting full or structured data.

Prefer the MCP server tools when the `recon` MCP is connected; otherwise:

```bash
recon <domain>
```

**Relay the CLI panel output verbatim.** Do not reformat it into Markdown bullets, tables, or headers. The panel is purpose-built and tighter than anything reformatted. End with a single short pointer such as *"Run with `--full` for everything, or ask me to `--explain` the reasoning."* Then stop. No interpretation, no commentary.

### Full / structured mode — `--full --json`

Trigger this mode when the user explicitly says "full", "max details", "give me everything", or when downstream automation needs structured data:

```bash
recon <domain> --full --json > recon-<domain>.json
```

In this mode, **do not dump the JSON inline.** It is several KB and consumes context for no benefit. Instead:

1. Save the JSON to a file in the current working directory (or a path the user specifies).
2. Reply with a 3-line headline only:
   > **{display_name}** — {provider}, confidence {confidence}.
   > {N services detected, {ct_subdomain_count} CT subdomains, email security {email_security_score}/5}.
   > Full JSON saved to `recon-{domain}.json`. Ready for the next ask.
3. Stop. Wait for the user.

If the user later asks for a structured summary of the JSON, follow the output-voice rules below.

## Preferring MCP over CLI

When the `recon` MCP server is connected, use it instead of shelling out — it returns parsed objects directly. Common starting points:

- `lookup_tenant(domain, format="json", explain=true)` — full domain intelligence with provenance.
- `analyze_posture(domain, profile=...)` — posture observations, optionally biased by a profile lens.
- `assess_exposure(domain)` — posture score (0–100). Operates on already-collected data; no extra network calls.
- `find_hardening_gaps(domain)` — categorized gaps with neutral "Consider" notes.
- `simulate_hardening(domain, fixes=[...])` — what-if scoring with hypothetical fixes applied.
- `compare_postures(domain_a, domain_b)` — side-by-side posture comparison.
- `cluster_verification_tokens(domains=[...])` — group domains by shared TXT site-verification tokens (hedged "possible relationship" signal).
- `chain_lookup(domain, depth)` — recursive related-domain discovery via CNAME and CT breadcrumbs.

Browse `recon://fingerprints`, `recon://signals`, and `recon://profiles` resources before guessing what recon can detect — they're free (no network) and return the live catalog.

CLI fallbacks when the MCP server is not connected:

- `recon <domain> --json` — structured output.
- `recon <domain> --explain` — full reasoning and provenance DAG.
- `recon batch <file> --json` — list of domains with cross-domain token clustering.
- `recon delta <domain>` — diff against the last cached snapshot. Relay verbatim like the default panel.

## Workflow patterns

Single-domain assessment (the common case):

1. `lookup_tenant` with `explain=true` to get identity, services, and provenance.
2. `assess_exposure` for the posture score.
3. `find_hardening_gaps` only if the user wants to discuss specific gaps.
4. `simulate_hardening` only if the user explicitly asks "what if we did X."

Vendor diligence across many domains:

1. `cluster_verification_tokens` over the list to find shared-credential clusters.
2. `lookup_tenant` only the domains the user wants to drill into — don't fan out unprompted.

Tracking change over time:

1. `recon delta <domain>` (CLI) compares against the cached snapshot. The output is a `DeltaReport` with explicit `added_*` / `removed_*` / `changed_*` fields. Report the deltas; do not narrate causes.

## Picking a profile

Profiles are posture lenses, not scores. They bias category emphasis. Pick based on what the *target* is, not what the user is:

- `fintech` — banks, payment processors, fintech.
- `healthcare` — hospitals, payers, health-tech.
- `saas-b2b` — B2B SaaS vendors.
- `high-value-target` — Fortune 500, defense contractors, large enterprises.
- `public-sector` — `.gov`, municipalities, agencies.
- `higher-ed` — universities, `.edu`.

If unsure, omit the profile. Don't guess from a thin hint. Custom profiles can live in `~/.recon/profiles/*.yaml`; check `recon://profiles` to enumerate.

## How to talk about the output

recon's voice is **hedged observation**, not verdict. Mirror that voice when reporting back.

- Say "DMARC policy is `p=none`" or "no DMARC record observed" — not "this domain is vulnerable."
- Say "Microsoft 365 tenant observed; identity is federated" — not "they use Okta" unless the IdP is explicitly named in the output (`google_idp_name` or evidence-backed insight).
- Say "passive observation only — there may be additional controls not visible in DNS" when summarizing posture, especially on sparse results.
- Surface the `confidence` field. `low` confidence with thin sources means "DNS is sparse for this org," not "this org is suspicious."
- Cite the evidence type when stating a fingerprint — MX, TXT, CNAME, NS, SRV, CAA, SPF, certificate SAN. Don't just assert.
- Never claim a vulnerability is *confirmed*. recon does not test exploitability. A missing DMARC record is a missing record; what it implies is a separate conversation.

When summarizing a `lookup_tenant` response, lead with what carries signal:

1. Tenant identity (`tenant_id`, `provider`, `auth_type`, `region`, `cloud_instance` if non-default).
2. Email configuration (`email_security_score`, `dmarc_policy`, `mta_sts_mode`, `email_gateway` if present).
3. Services grouped by category, not as a flat list.
4. Related domains only if the user asked for them.
5. Confidence and any `degraded_sources`.

Don't paste the raw JSON unless asked. Offer it.

## Sparse results

recon will sometimes return very little — a domain behind heavy proxies, with minimal published records, or one that doesn't expose SaaS verification tokens. This is expected. When it happens:

- Report what *was* observed, name the empty fields explicitly, and explain that passive collection has a ceiling for this kind of target.
- Check `degraded_sources` and `partial` — if a source failed transiently, suggest a re-run.
- Don't synthesize confidence that isn't there.

## Cache awareness

Every `TenantInfo` carries `resolved_at` (when the live resolution produced this result) and `cached_at` (when the cache entry was written; `null` on a fresh lookup). If the user asks for "current" data and `resolved_at` is older than they likely want, mention it and offer to re-resolve. Don't silently serve stale data as if it were fresh.

## Ephemeral fingerprints

If the user wants to test a hypothesis about a custom or internal SaaS — "does Contoso publish an Acme Platform verification token?" — use the ephemeral fingerprint workflow:

1. `inject_ephemeral_fingerprint(name, slug, category, confidence, detections=[...])`.
2. `reevaluate_domain(domain)` — uses cached data, no new network calls.
3. `clear_ephemeral_fingerprints()` when done.

Ephemeral fingerprints live only in the current MCP session and are quota-bounded.

## Hard rules

- recon is **passive**. Never claim it confirmed an active service, a running version, or an exploitable vulnerability. It infers from public records.
- Fingerprints are **probabilistic**. Detection scores (`low` / `medium` / `high`) reflect evidence corroboration, not ground truth.
- recon does **not require authorization** to query — every endpoint it touches is one anyone can hit with `dig` or a browser. Do not ask the user whether they have authorization to query a domain unless the user's stated intent suggests something other than legitimate research, due diligence, or defensive review.
- Output uses **neutral language**. No takeover hints, maturity verdicts, or offensive guidance. Mirror this in your reply.
