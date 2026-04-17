# Fingerprint Database

Fingerprints are loaded from `data/fingerprints.yaml` and validated on startup (schema, regex safety, required fields). Add new services by editing the YAML — no code changes needed.

## Custom Fingerprints

Drop a `fingerprints.yaml` in `~/.recon/` to add your own. Custom patterns are validated the same way — invalid regex or missing fields are skipped with a warning. Custom fingerprints are **additive only** — you cannot override or disable built-in fingerprints from the custom file.

Set `RECON_CONFIG_DIR` to override the custom fingerprint directory (default: `~/.recon/`).

```yaml
# ~/.recon/fingerprints.yaml
fingerprints:
  - name: Internal SSO Portal
    slug: internal-sso
    category: Security & Compliance
    confidence: high
    detections:
      - type: cname
        pattern: "sso\\.internal\\.example\\.com$"
        description: Internal SSO portal CNAME delegation
```

## Chained Patterns (`match_mode: all`)

By default, a fingerprint fires when **any** of its detections matches. For high-confidence attribution where a single record could be a false positive, use `match_mode: all` — the fingerprint only fires when **every** listed detection matches.

```yaml
fingerprints:
  - name: Corp Okta Tenant
    slug: corp-okta-confirmed
    category: Identity & Access
    confidence: high
    match_mode: all               # ALL detections must match
    detections:
      - type: cname
        pattern: "okta\\.com$"
        description: Okta SaaS CNAME
      - type: txt
        pattern: "^okta-verification="
        description: Okta domain verification TXT
```

**When to use chained patterns:**

- A single detection has a known false-positive pattern (e.g., a TXT token that shows up on dormant accounts).
- You want to require proof of both ownership (verification token) *and* active routing (MX/CNAME) before attributing the service.
- A pattern is too generic alone but diagnostic when combined with another record type.

**When NOT to use chained patterns:**

- A single unique TXT token (e.g., a service-specific prefix that no other service uses) is already diagnostic.
- Adding an `all` constraint would reject legitimate detections on domains that only have partial evidence (e.g., a registered M365 tenant without DKIM).

Chained patterns can cross record types — a `txt` + `cname` + `mx` combination is valid and only fires when all three records match on the same domain.

## Detection Types

| Type | What it queries | Matching | Best for |
|------|----------------|----------|----------|
| `txt` | TXT records at zone apex | Regex | Domain verification tokens (`^service-verify=`) |
| `spf` | SPF include directives | Substring | Email sending services (`sendgrid.net`) |
| `mx` | MX record hostnames | Substring | Email providers and gateways |
| `ns` | NS record hostnames | Substring | DNS hosting providers |
| `cname` | CNAME targets (www, root, subdomains) | Regex | CDN, WAF, and SaaS infrastructure |
| `subdomain_txt` | TXT at a specific subdomain | Regex | Site verification challenges (`_github-challenge-`) |
| `caa` | CAA record values | Substring | Certificate authority restrictions |
| `srv` | SRV record targets | Substring | Service discovery (Teams, XMPP) |

## Categories

AI & Generative, Productivity & Collaboration, CRM & Marketing, Security & Compliance, Support & Helpdesk, Email & Communication, DevTools & Infrastructure, Data & Analytics, HR & Operations, Payments & Finance, Sales Intelligence, Social & Advertising, Infrastructure, Misc.

## Email Security Score

The score counts five specific protections (1 point each):

| Points | Requires |
|--------|----------|
| 1 | DMARC policy is `reject` or `quarantine` (not `none`) |
| 1 | DKIM selectors found (Exchange or Google selectors) |
| 1 | SPF with `-all` (hard fail, not `~all` softfail) |
| 1 | MTA-STS record present |
| 1 | BIMI record present |

A domain with DMARC `none` + DKIM + SPF `~all` scores 1/5 (only DKIM counts).

## Related Domain Auto-Enrichment

Related domains are discovered via multiple techniques:

1. **CNAME breadcrumbs** — when autodiscover or DKIM delegation points to a different domain (e.g., `autodiscover.northwindtraders.com` → `northwind-internal.com`).
2. **Certificate transparency** — crt.sh discovers subdomains from public CT logs.
3. **Common subdomain probing** — ~45 high-signal prefixes (auth, login, sso, shop, api, status, cdn, staging, etc.) are probed directly via DNS CNAME lookups. This works even when crt.sh is down.
4. **Exchange on-prem detection** — OWA/autodiscover subdomain probing detects on-prem or hybrid Exchange deployments.
5. **SSO hub detection** — 15 identity-provider subdomain prefixes (Shibboleth, CAS, ADFS, Okta, SAML, university-specific SSO names) are probed via A-record resolution to detect federated identity hubs.
6. **A → PTR hosting detection** — apex A-record reverse DNS reveals cloud hosting providers (AWS, Azure, GCP, etc.).
7. **SPF redirect chain following** — SPF `redirect=` directives are followed up to 3 hops to discover the ultimate email policy domain.

Enrichment uses two tiers for efficiency:
- **Subdomains** of the queried domain get lightweight CNAME+TXT-only lookups (fast, ~2 DNS queries each).
- **Separate domains** (from CNAME breadcrumbs) get full DNS fingerprinting.

Subdomains are prioritized by signal value before the enrichment cap (25) is applied — auth/login/shop/api subdomains are enriched first, deep internal subdomains last. When crt.sh is unreachable, a note is shown in the output.
