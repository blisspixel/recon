# Known Limitations

recon is passive, zero-credential, and DNS/identity-endpoint-only. That gives
it stealth, speed, and legal clarity — but it also means there are whole
classes of information the tool cannot see. This doc is the honest inventory.

If any of these matter for your use case, either pipe recon's output into a
complementary tool (active scanner, authenticated API consumer) or accept the
gap as a known unknown.

---

## What recon cannot see

### Bundled platform services with no DNS footprint

- **Microsoft Copilot, Microsoft Teams Phone, Microsoft Purview** — included in
  M365 licenses with no public DNS verification token. recon infers Copilot
  as `(likely)` from M365 tenant presence (see Services > AI).
- **Google Gemini, Google Vault, Context-Aware Access** — same pattern;
  inferred from Google Workspace presence.
- **Most GitHub features** — private repos, actions, code scanning have no
  public DNS footprint even when the org is detectable elsewhere.

### Heavily proxied or zero-DNS domains

- **Cloudflare Email Routing** — MX points to Cloudflare, the backend mailbox
  provider is invisible.
- **Email security gateways** — when MX is Proofpoint / Mimecast / Trend
  Micro / Symantec, the actual email platform behind the gateway is only
  visible when DKIM also leaks it (recon does exactly this in v0.10.1).
- **Cloud-hosted landing pages** — when the entire domain is one A record
  pointing to a shared CDN and no SaaS verification tokens are published,
  there is nothing to detect.

### Internal-only services

- **Private SSO** (on-prem ADFS without public autodiscover, internal CAS,
  self-hosted Authelia / Keycloak not exposed via public DNS)
- **Internal SaaS** (company-internal Jira / Confluence behind VPN with no
  public CNAME)
- **Corporate file shares, intranet portals, internal ticketing** — all
  zero public DNS footprint by design.

### Network-level and host-level facts

- **Open ports, running services, OS versions** — these are active-scanning
  outputs. recon does not port-scan.
- **Web server software versions** — these come from HTTP responses, not
  DNS, and recon makes no HTTP requests to the target's own infrastructure.
- **TLS certificate chain details beyond CT metadata** — recon sees what CT
  logs contain (issuer, not_before/not_after, subject). For live certificate
  detail, use `openssl s_client` or an active TLS scanner.
- **IP-level infrastructure, ASN, BGP paths** — recon has no ASN / GeoIP /
  BGP datasets (see roadmap invariants).

---

## What recon underclaims on

These are cases where the tool hedges or shows a weaker signal than the
reality, because the evidence density doesn't justify a stronger claim.

### Bundled AI services

**Current:** `Microsoft Copilot (likely)` / `Google Gemini (likely)` even when
the organization has a fully provisioned Copilot deployment.

**Why hedged:** DNS has nothing to say about license SKU. We know the platform
exists; we infer the bundled AI is available. The `(likely)` qualifier is
load-bearing honesty, not cowardice.

### Dual-provider organizations

**Current:** A domain with M365 tenant + MX → Trend Micro gateway + DKIM for
M365 correctly reads as "Microsoft 365 via Trend Micro gateway". But if M365
is the only detected slug and Google Workspace slug fires only from a TXT
token (no DKIM, no MX), Google Workspace is **not shown** in the default
Provider line in v0.11 (see `--full` for account-only detections).

**Why underclaimed:** An M365 tenant with a dormant Google Workspace
registration is wildly common and doesn't mean active dual-platform email.
Showing both on every lookup was noise.

### Sovereignty when OIDC metadata is absent

**Current:** Government cloud (GCC, GCC High, DoD) detection depends on the
Microsoft OIDC discovery endpoint returning `cloud_instance` and
`tenant_region_sub_scope`. When a tenant is configured to suppress these
fields, recon treats the tenant as commercial.

**Why underclaimed:** There is no way to distinguish "commercial tenant" from
"sovereignty info stripped" from DNS alone. A domain-level hint would require
active probing, which is out of scope.

### Federated IdP vendor identification

**Current:** `Federated identity indicators (likely ADFS/Okta/Ping —
enterprise SSO)` when MX / UserRealm say federated but no IdP-specific slug
(okta / ping / onelogin / auth0) fires.

**Why hedged:** The federation protocol is observable; the vendor is not
reliably extractable from DNS alone.

---

## Known noise patterns

Times recon has been wrong in empirically verified ways:

- **crt.sh returning stale certs.** Cached certs for decommissioned subdomains
  can inflate the related-domain count. v0.10's per-domain CT cache means
  stale data is bounded, but a single crt.sh query can surface certs from
  years ago.
- **CertSpotter rate limits.** When crt.sh is down, CertSpotter is the
  fallback, but it rate-limits aggressively on larger domains. recon handles
  429 responses by returning partial data (documented in degraded-sources
  note) rather than crashing.
- **DKIM selector blind spots.** v0.10.1 expanded the probed selector set
  (`s1`, `s2`, `dkim`, `mail`, `k1`, `k2`, `default`). Services using
  non-standard selectors (e.g., `mcsv1._domainkey.` for some Mailchimp
  subaccounts) still produce "No DKIM observed" false negatives.
- **Domain homograph / Punycode.** recon normalizes to lowercase but does not
  attempt IDN → ASCII round-tripping. Punycode domains are handled, but the
  display name may not match what a user sees in a browser.
- **Wildcard DNS.** A domain with a catch-all wildcard A record at `*.domain`
  makes subdomain probing return a hit for every prefix, including ones that
  aren't actually distinct services. recon filters wildcard CT results but
  cannot fully neutralize wildcard A.

---

## When to reach for something else

| If you need… | Use instead |
|---|---|
| Live port/service enumeration | `nmap`, `masscan`, Project Discovery's `naabu` |
| Vulnerability assessment | Nessus, OpenVAS, `nuclei` |
| Authenticated Microsoft 365 enumeration | ROADtools, AADInternals (requires credentials) |
| Continuous monitoring / alerting | Commercial ASM (Bit Discovery, RiskIQ, CyCognito, Randori) |
| Phishing-level OSINT | Maltego, SpiderFoot, Amass |
| Certificate chain deep-dive | `openssl s_client`, `testssl.sh` |
| Subdomain takeover scanning | `subjack`, `nuclei` takeover templates (requires HTTP probing) |
| IP / ASN intelligence | ipinfo.io, Shodan, Censys (requires API keys) |
| Historical DNS | SecurityTrails, PassiveTotal, DomainTools (requires API keys) |

recon is deliberately a narrow tool. If you are doing any of the above, use
the right tool for the job — or pipe recon's `--json` output into it as a
starting point.

---

## Signal coverage and false positives

The fingerprint database (235 entries as of v0.11) is solo-maintained and
rule-based. A fingerprint match means "evidence fits this service's DNS
signature", not "this service is in use". Confident-looking output can still
be wrong.

Best practices:

- Treat outputs marked **Confidence: Low** or with **High (1 source)** as
  investigation leads, not conclusions.
- `--explain` shows the full evidence chain per signal. Use it when a
  specific claim matters.
- `--confidence-mode strict` only drops hedging when ≥3 sources corroborate
  AND confidence is High. Sparse-data output stays hedged by design.
- If you spot a false positive, open an issue with the domain and the
  incorrect detection. Fingerprint PRs are welcome — see
  [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Release & maintenance caveats

- **Solo maintainer.** The fingerprint database, signals, and profiles are
  maintained by one person. The community pipeline (v0.11) is the path to
  sharing that load; until then, coverage is constrained by one person's
  attention.
- **Upstream flakiness.** crt.sh, CertSpotter, and Microsoft / Google
  identity endpoints are not operated by the recon project. Outages
  propagate directly to recon output (documented via `degraded_sources`).
- **Point-in-time lookups.** recon reports what DNS says *now* (or what was
  cached recently). Continuous monitoring requires re-running on a schedule;
  `recon delta <domain>` is the supported workflow for run-over-run diffs.
