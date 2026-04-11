# Fingerprint Database

Fingerprints are loaded from `data/fingerprints.yaml` and validated on startup (schema, regex safety, required fields). Add new services by editing the YAML — no code changes needed.

## Custom Fingerprints

Drop a `fingerprints.yaml` in `~/.recon/` to add your own. Custom patterns are validated the same way — invalid regex or missing fields are skipped with a warning. Custom fingerprints are **additive only** — you cannot override or disable built-in fingerprints from the custom file.

Set `RECON_CONFIG_DIR` to override the custom fingerprint directory (default: `~/.recon/`).

## Detection Types

| Type | What it queries | Matching |
|------|----------------|----------|
| `txt` | TXT records at zone apex | Regex |
| `spf` | SPF include directives | Substring |
| `mx` | MX record hostnames | Substring |
| `ns` | NS record hostnames | Substring |
| `cname` | CNAME targets (www, root) | Substring |
| `subdomain_txt` | TXT at a specific subdomain | `subdomain:regex` format |
| `caa` | CAA record values | Substring |

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

When a domain's autodiscover CNAME or DKIM delegation points to a different domain (e.g., `autodiscover.northwindtraders.com` → `autodiscover.northwind-internal.com`), the tool automatically runs DNS fingerprinting on the related domain and merges the results. Certificate transparency logs (via crt.sh) also discover subdomains that may have their own SaaS verification records.
