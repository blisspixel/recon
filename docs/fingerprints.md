# Fingerprints

Fingerprints are DNS pattern rules in `recon_tool/data/fingerprints.yaml`.
235 built-in as of v1.0.2. Add new services by editing the YAML — no code
changes needed.

## Custom fingerprints

Drop `~/.recon/fingerprints.yaml`. Custom entries are validated on
startup; invalid regex or missing fields are skipped with a warning.
Custom fingerprints are **additive only** — you cannot override built-in
slugs from the custom file. Set `RECON_CONFIG_DIR` to override the
search directory.

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
```

## Detection types

| Type | Queries | Matching | Best for |
|------|---------|----------|----------|
| `txt` | TXT at zone apex | Regex | Verification tokens (`^service-verify=`) |
| `spf` | SPF includes | Substring | Email sending (`sendgrid.net`) |
| `mx` | MX hostnames | Substring | Email providers and gateways |
| `ns` | NS hostnames | Substring | DNS hosting |
| `cname` | CNAME targets | Regex | CDN / WAF / SaaS infrastructure |
| `subdomain_txt` | TXT at a specific subdomain | Regex | Challenge records (`_github-challenge-`) |
| `caa` | CAA values | Substring | CA restrictions |
| `srv` | SRV targets | Substring | Service discovery (Teams, XMPP) |

## Chained patterns (`match_mode: all`)

By default a fingerprint fires when *any* detection matches. Use
`match_mode: all` to require *every* detection — useful when a single
TXT or CNAME alone is ambiguous but the combination is diagnostic.

```yaml
- name: Corp Okta Tenant
  slug: corp-okta-confirmed
  category: Identity & Access
  confidence: high
  match_mode: all
  detections:
    - type: cname
      pattern: "okta\\.com$"
    - type: txt
      pattern: "^okta-verification="
```

**Use it when** a single detection false-positives on dormant accounts
or common-name TXT tokens, and you want both ownership evidence *and*
active routing before attributing the service.

**Skip it when** a unique service-specific TXT prefix already makes the
match diagnostic on its own. Forcing `all` can reject legitimate
detections on domains with partial evidence.

## Testing a new fingerprint

Before committing a new fingerprint to the built-in set:

1. Validate: `python scripts/validate_fingerprint.py ~/.recon/fingerprints.yaml`
2. Dry-run against a real domain that should match:
   `recon <domain> --explain --no-cache` — verify the slug fires and
   the evidence is what you expected.
3. Dry-run against 10-15 domains that should *not* match — especially
   parked / dormant / proxy-fronted domains. If your fingerprint fires
   on any of them, tighten the pattern or switch to `match_mode: all`.
4. Keep regexes anchored (`^`, `$`) where possible. Unanchored substring
   matches in TXT are the #1 source of false positives.

## Email security score

The score counts five apex-observable controls (1 point each):

| Points | Requires |
|--------|----------|
| 1 | DMARC policy is `reject` or `quarantine` (not `none`) |
| 1 | DKIM observed at common selectors, **or** inferred from a commercial email gateway (Proofpoint, Mimecast, Cisco IronPort, Barracuda, Trend Micro, Trellix, Symantec) with enforcing DMARC |
| 1 | SPF with `-all` (hard fail, not `~all` softfail) |
| 1 | MTA-STS record present |
| 1 | BIMI record present |

Score is an observation, not a verdict — we see apex DNS, not the full
posture. A domain with custom DKIM selectors we can't enumerate will
read low here even if DKIM is actually deployed; the gateway-inferred
DKIM path mitigates this for commercial-gateway deployments.

## Related-domain enrichment

When a primary lookup discovers related domains (from CNAME breadcrumbs
or certificate transparency), they get lightweight DNS probes and their
matched services fold back into the primary result. Prioritisation:
high-signal prefixes (`auth`, `login`, `sso`, `api`, `shop`) first,
capped at 15 enrichments per lookup to bound DNS fan-out.

CT providers (crt.sh, CertSpotter) fail open — if both are unreachable,
the per-domain CT cache serves as a fallback. See `docs/limitations.md`
for what CT degradation means for accuracy.
