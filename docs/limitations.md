# Known Limitations

recon is public-metadata-only and zero-credential. Its narrow collection
boundary limits target interaction, but it also means there are whole classes
of information the tool cannot see. The standard MTA-STS policy fetch is
target-visible, and opt-in direct probes add the documented CSE and BIMI
certificate requests. This document is the honest inventory, not a legal
opinion or a claim of invisibility.

If any of these matter for your use case, either pipe recon's output into a
complementary tool (active scanner, authenticated API consumer) or accept the
gap as a known unknown.

> **Surfaced in the panel (v1.9.9+).** When a queried apex looks sparse for
> its likely scale, the default panel adds a one-line "Passive-DNS ceiling"
> footer naming the categories of evidence that public DNS cannot reach. This
> page is the long-form inventory; the panel footer is the at-a-glance cue.

---

## What recon cannot see

### Bundled platform services with no DNS footprint

- **Microsoft Copilot, Microsoft Teams Phone, Microsoft Purview**: a public
  M365 tenant observation does not establish licensing, enablement, deployment,
  or use of these child products.
- **Google Gemini, Google Vault, Context-Aware Access**: a Google Workspace
  observation likewise does not establish child-product use.
- **Most GitHub features**: private repos, actions, code scanning have no
  public DNS footprint even when the org is detectable elsewhere.

### Heavily proxied or zero-DNS domains

- **Cloudflare Email Routing**: MX points to Cloudflare, the backend mailbox
  provider is invisible.
- **Email security gateways**: when MX is Proofpoint / Mimecast / Trend
  Micro / Symantec, the actual email platform behind the gateway is only
  visible when DKIM or other public records leak it.
- **Cloud-hosted landing pages**: when the entire domain is one A record
  pointing to a shared CDN and no SaaS verification tokens are published,
  there is nothing to detect.

See [correlation.md](correlation.md) for how the graph, temporal, and Bayesian
layers (shipped v1.7-v1.9, stable v2.0+) squeeze more usable defensive
intelligence from these minimal footprints: wildcard SAN siblings, CT issuance
bursts, and chain motifs all recover signal that single-record fingerprinting
cannot.

### Internal-only services

By default recon does not probe hosts, ports, login pages, or application
endpoints on the target's own infrastructure. The exceptions are narrow and
documented: it may fetch the standards-compliant MTA-STS policy at
`mta-sts.<domain>`, and the CSE / BIMI VMC direct probes run only when
`--direct-probes` is explicitly enabled.

- **Private SSO** (on-prem ADFS without public autodiscover, internal CAS,
  self-hosted Authelia / Keycloak not exposed via public DNS)
- **Internal SaaS** (company-internal Jira / Confluence behind VPN with no
  public CNAME)
- **Corporate file shares, intranet portals, internal ticketing**: all
  zero public DNS footprint by design.

### Regional and domestic SaaS ecosystems

- **Domestic provider stacks**: some APAC and China-focused organizations use
  domestic mail, collaboration, cloud, and identity providers whose public DNS
  patterns are not as well represented in the built-in catalog.
- **Localized verification schemes**: regional SaaS products may publish TXT
  or CNAME proofs that are stable but not yet fingerprinted.

When this happens, recon may show a low-signal or unclassified result even
though a rich domestic stack exists behind the scenes. Treat those results as
coverage gaps unless the public evidence directly supports a stronger claim;
do not infer that the stack is self-hosted.

### Network-level and host-level facts

- **Open ports, running services, OS versions**: these are active-scanning
  outputs. recon does not port-scan.
- **Web server software versions**: these come from generic HTTP responses, not
  DNS. recon does not request those pages; its only target-owned HTTP fetches are
  the documented MTA-STS policy request and opt-in CSE / BIMI VMC probes.
- **TLS certificate chain details beyond CT metadata**: recon sees what CT
  logs contain (issuer, not_before/not_after, subject). For live certificate
  detail, use `openssl s_client` or an active TLS scanner.
- **IP-level infrastructure, ASN, BGP paths**: recon has no ASN / GeoIP /
  BGP datasets (see roadmap invariants).

---

## Where recon must remain conservative

These are cases where the evidence does not justify a stronger claim. Some are
deliberate abstentions.

### Bundled AI services

**Current behavior:** Microsoft 365 and Google Workspace observations do not
produce Microsoft Copilot or Google Gemini labels. A child product appears only
when recon has a direct fingerprint for that product. Public DNS and tenant
metadata do not establish a child product's license, enablement, deployment, or
use.

### Dual-provider organizations

**Current:** A domain with M365 tenant + MX → Trend Micro gateway + DKIM for
M365 correctly reads as "Microsoft 365 via Trend Micro gateway". But if M365
is the only detected slug and Google Workspace fires only from a TXT token
(no DKIM, no MX), Google Workspace is treated as a weaker secondary/account
signal. Use `--full` when account-only detections matter.

**Why underclaimed:** An M365 tenant with a dormant Google Workspace
registration is wildly common and doesn't mean active dual-platform email.
Showing both on every lookup was noise.

### Sovereignty when OIDC metadata is absent

**Current:** Government cloud (GCC, GCC High, DoD) detection depends on the
Microsoft OIDC discovery endpoint returning `cloud_instance` and
`tenant_region_sub_scope`. When those fields are absent, recon preserves them
as unknown and emits no sovereignty conclusion.

**Why unresolved:** absent metadata cannot distinguish a commercial tenant from
suppressed or unavailable sovereignty metadata. This unknown-state behavior is
an invariant to preserve, not evidence of a commercial cloud.

### Federated IdP vendor identification

**Current:** `Federated identity indicators (likely ADFS/Okta/Ping,
enterprise SSO)` when MX / UserRealm say federated but no IdP-specific slug
(okta / ping / onelogin / auth0) fires.

**Why hedged:** The federation protocol is observable; the vendor is not
reliably extractable from DNS alone.

---

## Calibration and the validation ceiling

The `--fusion` posteriors and their 80% credible intervals are
**evidence-responsive**, not **calibrated** in the frequentist sense. The
interval widens as the public channel thins and narrows as evidence
accumulates (a construction property), but recon has not demonstrated that an
80% interval contains the truth 80% of the time, because the passive setting
has no ground-truth oracle to measure coverage against. Read the interval as
"how much the public channel constrains this claim," not as a validated
probability.

What is validated (numerical correctness, synthetic calibration, determinism,
sensitivity bounds) and the one experiment that would close the gap
(frequentist coverage against an independent label set) are in
[correlation.md](correlation.md) under Validation strategy. One honesty note
worth repeating from there: the headline real-corpus consistency number is
near-tautological by construction; it validates the inference plumbing, not the
CPT values.

---

## Known noise patterns

Times recon has been wrong in empirically verified ways:

- **crt.sh returning stale certs.** Cached certs for decommissioned subdomains
  can inflate the related-domain count. The per-domain CT cache bounds repeat
  exposure to flaky providers, but a single CT query can surface certs from
  years ago.
- **CertSpotter rate limits.** When crt.sh is down, CertSpotter is the
  fallback, but it rate-limits aggressively on larger domains. recon handles
  429 responses by returning partial data (documented in degraded-sources
  note) rather than crashing.
- **CT search is not complete inventory.** Public CT search APIs are indexed
  views over append-only logs and can be rate-limited, stale, partial, or
  missing an entry that another monitor sees. Treat CT evidence as passive
  certificate telemetry, not as an authoritative asset list.
- **DKIM selector blind spots.** recon probes common selectors such as `s1`,
  `s2`, `dkim`, `mail`, `k1`, `k2`, and `default`. Services using
  non-standard or per-account selectors (for example some Mailchimp, SendGrid,
  Salesforce Marketing Cloud, and regional providers) can still produce "No
  DKIM observed" false negatives.
- **Domain homograph / Punycode.** recon IDNA-encodes Unicode input and enforces
  a round-trip guard before analysis. This validation reduces ambiguous input;
  it does not make a Unicode display name safe from visual confusables or
  guarantee that it matches what a browser renders.
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
the right tool for the job, or pipe recon's `--json` output into it as a
starting point.

---

## Signal coverage and false positives

The fingerprint database is rule-based. A fingerprint match means "evidence
fits this service's DNS signature", not "this service is in use".
Confident-looking output can still be wrong.

Best practices:

- Treat outputs marked **Confidence: Low** or with **High (1 source)** as
  investigation leads, not conclusions.
- `--explain` shows the full evidence chain per signal. Use it when a
  specific claim matters.
- `--confidence-mode strict` or `--strict` only drops hedging when ≥3 sources corroborate
  AND confidence is High. Sparse-data output stays hedged by design.
- If you spot a false positive, open an issue with the domain and the
  incorrect detection. Fingerprint PRs are welcome, see
  [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Release & maintenance caveats

- **Solo maintainer.** The fingerprint database, signals, and profiles are
  maintained by one person. Fingerprint and signal PRs are the path to sharing
  that load; until then, coverage is constrained by one person's attention.
- **Upstream flakiness.** crt.sh, CertSpotter, and Microsoft / Google
  identity endpoints are not operated by the recon project. Outages
  propagate directly to recon output (documented via `degraded_sources`).
- **Point-in-time lookups.** recon reports what DNS says *now* (or what was
  cached recently). Continuous monitoring requires re-running on a schedule;
  `recon delta <domain>` is the supported workflow for run-over-run diffs.
