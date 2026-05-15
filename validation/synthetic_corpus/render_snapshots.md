# v1.9.9 panel render snapshots

Renders each fixture through the v1.9.9 ``render_tenant_panel``
function and captures the operator-facing output as plain
text. The agentic-UX harness (``validation/agentic_ux/run.py``)
can be pointed at these same fixtures to validate how an AI
agent reads the v1.9.9 panel; this report is the panel-shape
evidence that precedes the agent run.

Look for:

- ``Multi-cloud`` rows on multi-vendor fixtures.
- ``Passive-DNS ceiling`` blocks on sparse multi-domain fixtures.
- Per-vendor canonicalization (AWS-family collapses; Firebase
  rolls under GCP; Replit / Glitch excluded).
- No regression on pre-existing surfaces (Services, Confidence,
  External surface).

---

## v1.9.2: contoso-dense

Source: `validation/agentic_ux/fixtures/contoso-dense.json`

```
Contoso, Ltd
contoso.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (primary)
  Tenant       6babcaad-604b-40ac-a9d7-9fd97c0b779f • NA
  Auth         Managed
  Multi-cloud  2 providers observed (Akamai, Azure)
  Confidence   ●●● High (3 sources)


Services
  Email          Agari (DMARC)
  Identity       ADFS SSO hub
  Cloud          Azure DNS (DNS)
  AI             Microsoft Copilot (likely)
  Subdomain      Akamai (1)


High-signal related domains
  login.contoso.com, adfs.contoso.com, april7cert.sovnext.contoso.com,
  arcdirectconnect.adfs.contoso.com, auditnrt.protection.sovnext.contoso.com,
  authdal.protection.sovnext.contoso.com,
  authgls.protection.sovnext.contoso.com, autodiscover.contoso.com
  (32 total — 24 more, use --full to see all)

Insights
  Cloud-managed identity indicators (Entra ID native)
  Email security: DMARC reject, SPF strict
  DMARC Governance Investment: Agari
```

- Multi-cloud rollup: **fires**
- Passive-DNS ceiling: **suppressed**

## v1.9.2: hardened-sparse

`hardened-sparse.json` failed to load: Missing required fields: display_name, default_domain, queried_domain

## synth: azure_native_enterprise

Source: `validation/synthetic_corpus/fixtures/azure_native_enterprise.json`

```
Wingtip Toys
wingtip.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (account detected, no MX)
  Tenant       wingtip-azure
  Confidence   ●●● High (0 sources)


Services
  Email          Microsoft 365
  Cloud          Azure DNS (DNS), Azure CDN (CDN), Azure App Service,
                 Azure Blob Storage
  AI             Microsoft Copilot (likely)
  Subdomain      Azure App Service (1), Azure CDN (1)


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **fires**

## synth: cdn_fronted_minimal

Source: `validation/synthetic_corpus/fixtures/cdn_fronted_minimal.json`

```
Northwind Boutique
northwind-boutique.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Unknown (no known provider pattern matched)
  Tenant       northwind-cdn
  Confidence   ●●○ Medium (0 sources)


Services
  Cloud          Cloudflare (CDN)
  Business Apps  Shopify
  Subdomain      Shopify (1)
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **suppressed**

## synth: education_lms_heavy

Source: `validation/synthetic_corpus/fixtures/education_lms_heavy.json`

```
Trey University
trey-university.edu
──────────────────────────────────────────────────────────────────────────────
  Provider     Unknown (no known provider pattern matched)
  Tenant       trey-university
  Confidence   ●●● High (0 sources)


Services
  Email          Google Workspace
  Cloud          AWS Route 53 (DNS), AWS CloudFront (CDN)
  Collaboration  Canvas LMS (Instructure), Zoom
  Subdomain      AWS CloudFront (1), Canvas LMS (1)


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **fires**

## synth: empty_minimal

Source: `validation/synthetic_corpus/fixtures/empty_minimal.json`

```
Northwind Minimal
northwind-min.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Unknown (no known provider pattern matched)
  Tenant       northwind-min
  Confidence   ●○○ Low (0 sources)
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **suppressed**

## synth: fintech_high_security

Source: `validation/synthetic_corpus/fixtures/fintech_high_security.json`

```
Litware Capital
litware-capital.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (account detected, no MX)
  Tenant       litware-fin
  Multi-cloud  3 providers observed (AWS, Cloudflare, Fastly)
  Confidence   ●●● High (0 sources)


Services
  Email          Microsoft 365
  Identity       Okta
  Cloud          AWS CloudFront (CDN), AWS Route 53 (DNS),
                 Cloudflare (CDN)
  Security       Wiz Security, CrowdStrike Falcon, Snyk
  AI             Microsoft Copilot (likely)
  Business Apps  Wiz, CrowdStrike
  Subdomain      AWS CloudFront (1), Fastly (1), Okta (1)
```

- Multi-cloud rollup: **fires**
- Passive-DNS ceiling: **suppressed**

## synth: gcp_native_startup

Source: `validation/synthetic_corpus/fixtures/gcp_native_startup.json`

```
Tailspin Toys
tailspin.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Unknown (no known provider pattern matched)
  Tenant       tailspin-startup
  Confidence   ●●● High (0 sources)


Services
  Email          Google Workspace
  Cloud          Firebase Hosting, GCP Compute Engine (hosting),
                 Google Cloud Functions
  Business Apps  GCP Cloud Functions
  Subdomain      Firebase Hosting (1), GCP Cloud Functions (1)


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **fires**

## synth: google_workspace_aws_native

Source: `validation/synthetic_corpus/fixtures/google_workspace_aws_native.json`

```
Northwind Traders
northwind.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Unknown (no known provider pattern matched)
  Tenant       northwind-eng
  Confidence   ●●● High (0 sources)


Services
  Email          Google Workspace
  Cloud          AWS Route 53 (DNS), AWS CloudFront (CDN), AWS S3
  Collaboration  GitHub, Slack
  Subdomain      AWS CloudFront (2), AWS S3 (1)


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **fires**

## synth: hardened_minimal_dns

Source: `validation/synthetic_corpus/fixtures/hardened_minimal_dns.json`

```
Adatum Corporation
adatum.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Unknown (no known provider pattern matched)
  Tenant       adatum-hard
  Confidence   ●○○ Low (0 sources)


Services
  Cloud          Cloudflare (CDN)


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **fires**

## synth: healthcare_compliance

Source: `validation/synthetic_corpus/fixtures/healthcare_compliance.json`

```
Adatum Health
adatum-health.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (account detected, no MX)
  Tenant       adatum-health
  Multi-cloud  2 providers observed (AWS, Cloudflare)
  Confidence   ●●● High (0 sources)


Services
  Email          Microsoft 365
  Identity       Okta
  Cloud          Cloudflare (CDN), AWS CloudFront (CDN)
  Security       Wiz Security, CrowdStrike Falcon
  AI             Microsoft Copilot (likely)
  Business Apps  Wiz, CrowdStrike
  Subdomain      AWS CloudFront (1), Okta (1)
```

- Multi-cloud rollup: **fires**
- Passive-DNS ceiling: **suppressed**

## synth: heroku_legacy_app

Source: `validation/synthetic_corpus/fixtures/heroku_legacy_app.json`

```
Contoso Legacy Apps
contoso-legacy.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (account detected, no MX)
  Tenant       contoso-legacy
  Multi-cloud  2 providers observed (Heroku, Cloudflare)
  Confidence   ●●○ Medium (0 sources)


Services
  Email          Microsoft 365
  Cloud          Heroku, Cloudflare (CDN)
  AI             Microsoft Copilot (likely)
  Collaboration  GitHub
  Subdomain      Heroku (1)


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **fires**
- Passive-DNS ceiling: **fires**

## synth: hybrid_dual_email

Source: `validation/synthetic_corpus/fixtures/hybrid_dual_email.json`

```
Contoso Mergers
contoso-merger.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (account detected, no MX)
  Tenant       contoso-hybrid
  Multi-cloud  2 providers observed (AWS, Cloudflare)
  Confidence   ●●○ Medium (0 sources)


Services
  Email          Microsoft 365, Google Workspace
  Identity       Okta
  Cloud          AWS Route 53 (DNS), Cloudflare (CDN)
  AI             Microsoft Copilot (likely)
  Subdomain      AWS CloudFront (1), Okta (1)


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **fires**
- Passive-DNS ceiling: **fires**

## synth: m365_okta_enterprise

Source: `validation/synthetic_corpus/fixtures/m365_okta_enterprise.json`

```
Contoso Ltd
contoso.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (account detected, no MX)
  Tenant       contoso-mid
  Multi-cloud  3 providers observed (AWS, Cloudflare, Fastly)
  Confidence   ●●● High (0 sources)


Services
  Email          Microsoft 365
  Identity       Okta
  Cloud          Cloudflare (CDN), AWS CloudFront (CDN)
  Security       Wiz Security
  AI             Microsoft Copilot (likely)
  Collaboration  Slack, Atlassian (Jira/Confluence)
  Business Apps  Wiz
  Subdomain      AWS CloudFront (2), Fastly (1), Zendesk (1)
```

- Multi-cloud rollup: **fires**
- Passive-DNS ceiling: **suppressed**

## synth: media_publisher_heavy_cdn

Source: `validation/synthetic_corpus/fixtures/media_publisher_heavy_cdn.json`

```
Wingtip Media
wingtip-media.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Unknown (no known provider pattern matched)
  Tenant       wingtip-media
  Multi-cloud  3 providers observed (Fastly, AWS, Cloudflare)
  Confidence   ●●● High (0 sources)


Services
  Email          Google Workspace
  Cloud          Cloudflare (CDN), Fastly (CDN), AWS S3,
                 AWS CloudFront (CDN)
  Subdomain      Fastly (8), AWS CloudFront (1)
```

- Multi-cloud rollup: **fires**
- Passive-DNS ceiling: **suppressed**

## synth: multi_cloud_saas_heavy

Source: `validation/synthetic_corpus/fixtures/multi_cloud_saas_heavy.json`

```
Fabrikam, Inc.
fabrikam.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (account detected, no MX)
  Tenant       fabrikam-saas
  Multi-cloud  4 providers observed (AWS, GCP, Cloudflare, Fastly)
  Confidence   ●●● High (0 sources)


Services
  Email          Microsoft 365
  Cloud          Cloudflare (CDN), AWS CloudFront (CDN),
                 GCP Compute Engine (hosting)
  AI             Microsoft Copilot (likely)
  Collaboration  Slack
  Business Apps  Snowflake
  Subdomain      AWS CloudFront (1), Atlassian Statuspage (1), +3 more
```

- Multi-cloud rollup: **fires**
- Passive-DNS ceiling: **suppressed**

## synth: public_sector_hardened

Source: `validation/synthetic_corpus/fixtures/public_sector_hardened.json`

```
Tailspin Public Services
tailspin-public.gov
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (account detected, no MX)
  Tenant       tailspin-gov
  Confidence   ●○○ Low (0 sources)


Services
  Email          Microsoft 365
  Cloud          AWS Route 53 (DNS)
  AI             Microsoft Copilot (likely)


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **fires**

## synth: saas_only_no_cloud

Source: `validation/synthetic_corpus/fixtures/saas_only_no_cloud.json`

```
Trey Research
treyresearch.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (account detected, no MX)
  Tenant       treyresearch-saas
  Confidence   ●●● High (0 sources)


Services
  Email          Microsoft 365
  AI             Microsoft Copilot (likely)
  Collaboration  Slack, Atlassian (Jira/Confluence)
  Business Apps  Salesforce, HubSpot


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **fires**

## synth: small_single_domain_org

Source: `validation/synthetic_corpus/fixtures/small_single_domain_org.json`

```
Litware, Inc.
litware.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (account detected, no MX)
  Tenant       litware-small
  Confidence   ●●● High (0 sources)


Services
  Email          Microsoft 365
  AI             Microsoft Copilot (likely)
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **suppressed**

## synth: two_aws_slugs_one_vendor

Source: `validation/synthetic_corpus/fixtures/two_aws_slugs_one_vendor.json`

```
Fabrikam Cloud Services
fabrikam-cloud.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Unknown (no known provider pattern matched)
  Tenant       fabrikam-aws-only
  Confidence   ●●● High (0 sources)


Services
  Cloud          AWS Route 53 (DNS), AWS CloudFront (CDN), AWS S3,
                 AWS EC2 (hosting)


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **suppressed**
- Passive-DNS ceiling: **fires**

## synth: vercel_jamstack

Source: `validation/synthetic_corpus/fixtures/vercel_jamstack.json`

```
Fabrikam Marketing
fabrikam-marketing.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Unknown (no known provider pattern matched)
  Tenant       fabrikam-jam
  Multi-cloud  2 providers observed (Vercel, Cloudflare)
  Confidence   ●●● High (0 sources)


Services
  Email          Google Workspace
  Cloud          Vercel (edge), Cloudflare (CDN)
  Collaboration  GitHub
  Business Apps  Stripe
  Subdomain      Vercel (2)


Passive-DNS ceiling
  Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and
  SaaS without DNS verification do not appear in public DNS records.
```

- Multi-cloud rollup: **fires**
- Passive-DNS ceiling: **fires**
