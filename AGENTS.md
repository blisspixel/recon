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

## Detecting whether MCP is connected

Before choosing CLI vs MCP, look at your own available-tools list. If you see `recon:*` tools (e.g. `mcp__recon__lookup_tenant`, `mcp__recon__analyze_posture`), the MCP server is connected — prefer those. If you do not, fall back to the CLI. Do not call an MCP tool speculatively to test connectivity.

## Domain validation before any CLI invocation (mandatory)

When falling back to the CLI, **never** interpolate a user- or context-supplied domain into a Bash command without first validating it against this exact pattern:

```
^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$
```

Lowercase the input, strip any leading `https://` / `http://` / `www.`, then match. If the resulting string does **not** match — including any presence of whitespace, quotes, `;`, `|`, `&`, `$`, backticks, parentheses, redirection (`>` `<`), path components (`/` `\`), or non-ASCII — refuse to run the command and tell the user the domain is malformed. Do not "fix it up" by stripping characters; reject the input.

Pass the validated domain inside double quotes in the Bash command (`recon "validated.example.com"`) as defense-in-depth; the regex is the primary control. The MCP path takes structured arguments and is not subject to this rule.

## Two invocation modes

### Default mode — panel output

Use this when the user asks recon-shaped questions conversationally — "recon contoso.com", "what does pokemon.com run on" — without explicitly requesting full or structured data.

When MCP is connected, call `lookup_tenant(domain)` and reformat to a panel-equivalent summary. Otherwise shell out (after validating `<domain>` per the rule above):

```bash
recon "<domain>"
```

**Relay the CLI panel output verbatim.** Do not reformat it into Markdown bullets, tables, or headers. The panel is purpose-built and tighter than anything reformatted. End with a single short pointer such as *"Run with `--full` for everything, or ask me to `--explain` the reasoning."* Then stop. No interpretation, no commentary.

<details>
<summary>Sample panel (collapsed)</summary>

```
Contoso Ltd
contoso.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (primary) via Proofpoint gateway + Google Workspace (secondary)
  Tenant       a1b2c3d4-e5f6-7890-abcd-ef1234567890 • NA
  Auth         Federated (Entra ID + Google Workspace)
  Confidence   ●●● High (4 sources)

Services
  Email          Microsoft 365, Google Workspace, Proofpoint, DMARC, DKIM,
                 SPF: strict (-all), BIMI
  Identity       Okta, Google Workspace (managed identity)
  Cloud          Cloudflare (CDN), AWS Route 53 (DNS)
  Security       Wiz, CAA: 3 issuers restricted
  Collaboration  Slack, Atlassian (Jira/Confluence)

Insights
  Federated identity indicators observed (likely Okta — enterprise SSO)
  Email security 4/5: DMARC reject, DKIM, SPF strict, BIMI
  Email gateway: Proofpoint in front of Exchange
```

That is the shape recon emits. Pass it through unchanged.

</details>

### Full / structured mode — `--full --json`

Trigger this mode when the user explicitly says "full", "max details", "give me everything", or when downstream automation needs structured data. Do **not** use shell redirection; capture stdout and write the file with your own file-write tool:

```bash
recon "<domain>" --full --json
```

In this mode, **do not dump the JSON inline.** Output is typically 3–10 KB depending on org size and consumes context for no benefit. Instead:

1. Capture stdout from the Bash call. Use your file-write tool to save it to `recon-<validated-domain>.json` in the current working directory (or a path the user specifies). Never substitute the unvalidated domain into a shell redirect.
2. Reply with a 3-line headline only (field names per [`docs/recon-schema.json`](docs/recon-schema.json) v1.0 contract):
   > **{display_name}** — {provider}, confidence {confidence}.
   > {N services detected, {ct_subdomain_count} CT subdomains, email security {email_security_score}/5}.
   > Full JSON saved to `recon-{domain}.json`. Ready for the next ask.
3. Stop. Wait for the user.

If the user later asks for a structured summary of the JSON, follow the output-voice rules below.

### Explain mode — `--explain`

Use when the user asks "why", "how do you know", or "show your reasoning". The CLI emits the panel plus a provenance DAG (`evidence → slug → rule → signal → insight`). The MCP `lookup_tenant(domain, explain=true)` returns the same chain as a structured `explanation_dag` field for programmatic consumption.

Surface the *summary* of the chain — which evidence drove which insight — rather than dumping the full DAG. Offer the full DAG on follow-up.

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

1. `recon delta <domain>` (CLI) compares the current resolution against the cached snapshot at `~/.recon/cache/`. The output is a `DeltaReport` (see `$defs/DeltaReport` in `docs/recon-schema.json`) with explicit `added_*` / `removed_*` / `changed_*` fields. Report the deltas; do not narrate causes.
2. **First-run case.** A domain that has never been resolved on this machine has no baseline. `recon delta` returns an empty diff in that case — surface this explicitly ("no prior snapshot — this is the first lookup, so nothing to compare against") rather than reporting "no changes" as if change had been ruled out.

## Picking a profile

Profiles are posture lenses, not scores. They bias category emphasis. Pick based on what the *target* is, not what the user is:

- `fintech` — banks, payment processors, fintech.
- `healthcare` — hospitals, payers, health-tech.
- `saas-b2b` — B2B SaaS vendors.
- `high-value-target` — Fortune 500, defense contractors, large enterprises.
- `public-sector` — `.gov`, municipalities, agencies.
- `higher-ed` — universities, `.edu`.

If unsure, omit the profile. Don't guess from a thin hint. Custom profiles can live in `~/.recon/profiles/*.yaml`; check `recon://profiles` to enumerate.

Invocation:

- CLI: `recon <domain> --profile <name>` (also accepted by `recon <domain> --full --profile <name>`).
- MCP: `analyze_posture(domain, profile="<name>")` — profile is the second argument.

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
