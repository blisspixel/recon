# Fingerprints

Fingerprints are DNS pattern rules in `recon_tool/data/fingerprints/`,
one YAML file per category (`ai.yaml`, `email.yaml`, `security.yaml`,
`infrastructure.yaml`, `productivity.yaml`, `crm-marketing.yaml`,
`data-analytics.yaml`, `verticals.yaml`). Add new services by editing
the matching category file — no code changes needed. Use
`recon fingerprints list` / `search` / `show` to inspect the current
catalog without opening YAML.

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
| `subdomain_txt` | TXT at a specific subdomain | `subdomain:regex` | Challenge records (`_vendor-challenge:.+`) |
| `caa` | CAA values | Substring | CA restrictions |
| `srv` | SRV targets | Substring | Service discovery (Teams, XMPP) |

## Metadata fields

Detection rules can include optional metadata:

```yaml
detections:
  - type: txt
    pattern: "^service-domain-verification="
    description: Vendor domain-ownership verification token
    reference: https://vendor.example/docs/domain-verification
    weight: 0.8
```

Use `description` for the observable meaning of the record, not a maturity or
risk judgment. Add `reference` when the vendor has public verification docs.
Use non-default `weight` sparingly, when a detection is useful but weaker than
the rest of the fingerprint.

Metadata feeds `recon fingerprints show`, MCP catalog resources, explanation
output, and validation reports. Improving descriptions and references is a
safe way to increase explainability without changing detection behavior.

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
5. Add `description` and, when public vendor docs exist, `reference` metadata
   so `--explain` and MCP consumers can show why the record mattered.
6. If you add or change multiple detections on one fingerprint, run
   `python -m validation.audit_fingerprints` and record whether the entry
   should stay `any`, move to `match_mode: all`, or be tightened first.
7. If the service has common legitimate configurations that publish little or
   no DNS evidence, add a short PR note or weak-area doc update rather than
   making the fingerprint broader.

## False positives we avoid

Patterns that have caused bad detections and should not be repeated:

- **Unanchored TXT regexes.** Prefer service-specific prefixes and anchors.
- **Dormant ownership tokens.** A lone verification TXT can mean an abandoned
  trial account; use `match_mode: all` when routing evidence is available.
- **Wildcard A/CNAME zones.** Do not infer a service from a subdomain name
  alone when wildcard DNS can manufacture every prefix.
- **Generic product subdomains.** `grafana.example.com` or `n8n.example.com`
  is not enough; recon intentionally avoids generic service-name matching.
- **Shared CDN hostnames.** A CDN edge proves the edge provider, not the app
  running behind it.

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
