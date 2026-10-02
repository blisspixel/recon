# Fingerprints

Fingerprints are public-metadata pattern rules in
`src/recon_tool/data/fingerprints/`, split by catalog concern across
`ai.yaml`, `crm-marketing.yaml`, `data-analytics.yaml`,
`discovered-signals.yaml`, `email.yaml`, `infrastructure.yaml`,
`productivity.yaml`, `security.yaml`, `surface.yaml`, `verifications.yaml`,
and `verticals.yaml`. Add new services by editing the matching catalog file;
no code changes are needed. Use
`recon fingerprints list` / `search` / `show` to inspect the current
catalog without opening YAML.

The split YAML files are the canonical reviewed source and remain in the source
distribution. A deterministic generated JSON artifact is the only built-in
catalog representation shipped in the wheel. CI proves byte-for-byte currency,
and differential tests prove exact ordered equality with the YAML source. Run
`uv run python scripts/generate_fingerprint_catalog.py --write` after changing
built-ins. Custom YAML remains runtime parsed and validated.

## Agent discovery declarations

The `crewai-aid` slug is retained for compatibility but identifies the
vendor-neutral **Agent Identity & Discovery (AID)** declaration. It recognizes
current `aid2` and legacy `aid1` version fields at `_agent.<domain>` using the
[AID specification](https://github.com/agentcommunity/agent-identity-discovery/blob/main/packages/docs/specification.md).
It does not identify CrewAI or validate a complete AID record. The separate
`mcp-discovery` rule recognizes a
[community DNS proposal](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2368),
not an adopted MCP discovery standard. Neither declaration contributes an
AI-platform or autonomous-agent deployment claim.

These are DNS observations only. recon does not fetch advertised endpoints,
agent cards or proof challenges. The
[A2A 1.0 specification](https://a2a-protocol.org/v1.0.0/specification/)
defines agent-card discovery, but recon does not implement an A2A client or
server. Ordinary apex normalization still applies; use `--exact` for a literal
sub-host query. Detection is not AID client conformance or A2A compatibility.

## Custom fingerprints

Drop a `fingerprints.yaml` in recon's config directory, or split it across a
`fingerprints/` directory beside it. Both are read and both are additive.

**The config directory is resolved, not fixed.** In precedence order:

| Condition | Config directory |
|---|---|
| `RECON_CONFIG_DIR` is set | that directory |
| `~/.recon/` already exists (legacy install) | `~/.recon/` |
| otherwise (fresh install) | `$XDG_CONFIG_HOME/recon`, default `~/.config/recon/` |

A fresh install on Linux or macOS therefore wants
`~/.config/recon/fingerprints.yaml`, not `~/.recon/fingerprints.yaml`. Do not
guess: `recon doctor` prints the exact resolved path on its **Custom
fingerprints** row, whether or not the file exists yet. The rule lives in
[`paths.py`](../src/recon_tool/paths.py).

Custom entries are validated on startup; invalid regex or missing fields are
skipped with a warning. Custom fingerprints are **additive only:** you cannot
override built-in slugs from the custom file. Under the long-running MCP
server, call `reload_data` after editing so the process picks the change up.

```yaml
# <config dir>/fingerprints.yaml (run `recon doctor` for the resolved path)
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
| `spf` | Parsed SPF include and redirect targets | DNS-label suffix | Published sending delegation (`sendgrid.net`) |
| `mx` | MX hostnames | DNS-label suffix | Email routing providers and gateways |
| `ns` | NS hostnames | DNS-label suffix for dotted patterns; dotless legacy fragments match a label or its hyphenated prefix | DNS delegation |
| `cname` | CNAME targets | Regex | CDN / WAF / SaaS infrastructure |
| `cname_target` | CNAME chain target | Regex (+ `tier`) | SaaS / infrastructure attribution via CNAME chains; carries a `tier` (`application` or `infrastructure`) that surface attribution uses to rank a chain. The most common detection type in the catalog. |
| `subdomain_txt` | TXT at a specific subdomain | `subdomain:regex` | Challenge records (`_vendor-challenge:.+`) |
| `caa` | CAA values | Substring | CA restrictions |
| `srv` | Bounded common SRV targets | DNS-label suffix; dotless patterns use substring matching | Service discovery (Teams, XMPP) |
| `dmarc_rua` | DMARC `rua=` report URI | Substring | DMARC aggregate-report processor / vendor (the report mailbox host) |

Adobe's `adobe-idp-site-verification=` TXT marker is displayed as **Adobe Admin
Console** under Business Apps. It is a
[domain-verification marker](https://helpx.adobe.com/business/enterprise/directories-domains-access/directories-and-domains/verify-domain-ownership.html),
not evidence that Adobe is the organization's identity provider. The marker
does not establish completed verification, SSO, licenses, or active product
use. Adobe supports both externally authenticated Federated ID and Adobe-authenticated
Enterprise ID; see [Adobe identity types](https://helpx.adobe.com/business/enterprise/identity-sso/set-up-identity/identity-types.html).
The historical `adobe-idp` slug remains stable for automation.

The built-in `null-mx` observation requires `0 .` as the sole distinct MX
record, as specified in [RFC 7505 section 3](https://www.rfc-editor.org/rfc/rfc7505.html#section-3).
Mixed sets and malformed root targets retain their raw evidence without a
no-mail claim. Ordinary MX hosts in a mixed set still receive their normal
catalog classification. This reports the published declaration, not a mail
delivery test; missing MX records alone do not establish that email is absent.

SPF provider matching requires the complete `v=spf1` version token. It uses
include references before the first `all` mechanism and a single effective
`redirect=` modifier. All include qualifiers remain policy references, not
proof of sender authorization. An `all` mechanism makes redirect ineffective
wherever it appears.
The bounded redirect collector applies that rule at every hop. See
[RFC 7208 sections 4.5, 4.6.2, 5.1 and 6.1](https://www.rfc-editor.org/rfc/rfc7208.html).

Specificity is resolved per SPF target, so an overlapping rule cannot hide a
different, independently listed target. Live detection and cache-only replay
share this behavior and preserve the original record as evidence. This is a
bounded observation parser, not full SPF validation or sender-IP evaluation;
recon does not recursively expand includes or evaluate SPF macros.

DKIM TXT observations at the existing Google and generic selectors share a
bounded tag-list parser. It respects the case-sensitive, optional `v=DKIM1`
tag, rejects duplicate or malformed tags, and requires nonempty base64 `p=`
material. Empty `p=` is a revoked key and does not create a DKIM control.
Omitted `v=` uses the specified default. Original admitted records remain the
evidence values. See [RFC 6376 sections 3.2 and 3.6.1](https://www.rfc-editor.org/rfc/rfc6376.html).

This check admits record shape only; it does not validate cryptographic key
structure, strength, algorithms, signed messages, or active signing. Existing
CNAME observations remain delegation indicators. It adds no selectors or
network requests and does not reinterpret previously cached results.

## Metadata fields

The required `confidence` value (`low`, `medium`, or `high`) is a reviewed
rule-level evidence-strength tier. It is not a calibrated probability, a claim
that the service is active, or a substitute for the record-role description.

Detection rules can include optional metadata:

```yaml
detections:
  - type: txt
    pattern: "^service-domain-verification="
    description: Vendor-issued domain-verification token
    reference: https://vendor.example/docs/domain-verification
    weight: 0.8
    verified: 2026-07-03
```

Use `description` for the observable meaning of the record, not a maturity or
risk judgment. Add `reference` when the vendor has public verification docs.
Use non-default `weight` sparingly, when a detection is useful but weaker than
the rest of the fingerprint. Set `verified` (`YYYY-MM-DD`) to the date the
pattern was last confirmed against a public source or disclosure-safe corpus
observation. It does not affect matching and drives the freshness auditor
(`python -m validation.audit_fingerprints --freshness`). New detections require
a valid, non-future date; legacy undated detections remain a reviewed backfill
queue. A freshness pass can change family wording without adding a rule: if
the vendor now documents a newer default and still supports the older host,
keep both patterns, date both, and stop calling the older host current.
See [catalog-strategy.md](catalog-strategy.md).

Metadata feeds `recon fingerprints show`, MCP catalog resources, explanation
output, and validation reports. Improving descriptions and references is a
safe way to increase explainability without changing detection behavior.

## Chained patterns (`match_mode: all`)

By default a fingerprint fires when *any* detection matches. Use
`match_mode: all` to require *every* detection, useful when a single
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
or common-name TXT tokens, and you want both administrative-token evidence
*and* routing-configuration evidence before attributing the observed pattern.

**Skip it when** a unique service-specific TXT prefix already makes the
match diagnostic on its own. Forcing `all` can reject legitimate
detections on domains with partial evidence.

## Testing a new fingerprint

Testing new fingerprints is part of the broader correlation engine work
described in [correlation.md](correlation.md). Every new detection rule is
judged by how much additional signal it recovers on hardened targets without
violating the hedging or provenance invariants.

Before committing a new fingerprint to the built-in set:

1. Validate: `python scripts/validate_fingerprint.py <config dir>/fingerprints.yaml`
   (`recon doctor` prints the resolved config directory)
2. Prove the positive path with a minimal reserved synthetic fixture. If live
   validation is needed, keep every real apex and result under the gitignored
   `validation/corpus-private/` and `validation/runs-private/` workspaces.
3. Check negative cases with reserved synthetic fixtures and, when useful, a
   private local domain set that includes parked, dormant, and proxy-fronted
   shapes. If the fingerprint fires unexpectedly, tighten the pattern or switch
   to `match_mode: all`. Commit only the fixtures and disclosure-safe aggregate
   summary, never the real domain list or per-domain output.
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
- **Dormant verification tokens.** A lone verification TXT can mean an abandoned
  trial account; use `match_mode: all` when routing evidence is available.
- **Wildcard A/CNAME zones.** Do not infer a service from a subdomain name
  alone when wildcard DNS can manufacture every prefix.
- **Generic product subdomains.** `grafana.example.com` or `n8n.example.com`
  is not enough; recon intentionally avoids generic service-name matching.
- **Shared CDN hostnames.** A matching CDN edge supports attribution of the
  observed routing chain to that edge provider, not the application behind it.
- **Patterns that would collapse sparse evidence into confident-looking
  claims.** See the deterministic-correlation section of
  [correlation.md](correlation.md) for the full reasoning: when a target
  publishes very little, the right answer is wider hedges, not a tighter
  pattern that pretends to know more.

## Email security score

The compatibility score counts five publicly observable controls (1 point
each):

| Points | Requires |
|--------|----------|
| 1 | Effective DMARC policy remains `reject` or `quarantine` after `pct=` and testing-mode compatibility downgrades |
| 1 | DKIM observed at common selectors |
| 1 | SPF with `-all` (hard fail, not `~all` softfail) |
| 1 | MTA-STS record present |
| 1 | BIMI record present |

Score is an observation, not a verdict: we see apex DNS, not the full
posture. A domain with custom DKIM selectors we can't enumerate will
read low here even if DKIM is actually deployed. A commercial gateway plus
enforcing DMARC does not receive DKIM credit because neither observation
establishes that a DKIM key was published or used.

## Related-domain enrichment

When a primary lookup discovers related names from CNAME, DKIM, autodiscover,
or certificate-transparency breadcrumbs, it performs at most 15 bounded
follow-up DNS enrichments, prioritizing high-signal prefixes such as `auth`,
`login`, `sso`, `api`, and `shop`.

The scope split matters. A `cname_target` match on a related subdomain is kept
as a per-subdomain `surface_attributions` entry and is not added to the apex
service or slug set. Other service and slug inventory returned by the legacy
related-enrichment path can fold into top-level `services` and `slugs`, but its
raw records do not become apex `evidence`, `detection_scores`, email-provider
fields, or exposure controls. Neither path establishes active use, ownership,
or an organizational relationship.

CT providers (crt.sh, CertSpotter) fail open: if both are unreachable,
the per-domain CT cache serves as a fallback. See `docs/limitations.md`
for what CT degradation means for accuracy.
