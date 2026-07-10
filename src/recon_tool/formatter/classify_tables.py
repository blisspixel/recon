"""Service-classification data tables.

Pure data shared by the classification logic in
``recon_tool.formatter.classify`` and, through it, every formatter renderer:
slug -> display category, slug -> cloud
vendor, display-name overrides, and the keyword / prefix / suffix sets the
two-pass categorizer matches against. No logic and no imports, just the
literals, kept in their own module so neither the logic module nor
the formatter facade carries an 850-line data block.

These are public (no leading underscore): they cross a module boundary, and the
repo's pyright-strict gate treats cross-module underscore access as private
usage. The formatter facade re-exports them under their historical ``_NAME``
aliases.
"""

from __future__ import annotations

__all__ = [
    "CATEGORY_BY_SLUG",
    "CLOUD_SLUG_QUALIFIERS",
    "CLOUD_VENDOR_BY_SLUG",
    "CLOUD_VENDOR_ROLLUP_EXCLUSIONS",
    "EMAIL_SERVICE_PREFIXES",
    "FILTERED_SERVICE_PREFIXES",
    "FILTERED_SERVICE_SUFFIXES",
    "M365_KEYWORDS",
    "SERVICE_CATEGORIES_ORDER",
    "SLUG_DISPLAY_OVERRIDES",
]

# Exact M365 service-name fallbacks for source-derived labels without
# ``provider_group`` metadata. Fingerprint metadata remains authoritative.
# Keep these exact: broad substrings such as "microsoft" or "dkim" misclassify
# unrelated products and generic email controls.
M365_KEYWORDS = frozenset(
    {
        "dkim (exchange online)",
        "exchange autodiscover",
        "exchange online",
        "intune / mdm",
        "microsoft 365",
        "microsoft 365 (us government cloud)",
        "microsoft teams",
        "office proplus (msoid)",
    }
)
# Category display order. Each service is classified into exactly one
# of these by categorize_service; "Business Apps" is the fallback.
SERVICE_CATEGORIES_ORDER: tuple[str, ...] = (
    "Email",
    "Identity",
    "Cloud",
    "Security",
    "AI",
    "Data & Analytics",
    "Collaboration",
    "Business Apps",
)
# Service → display-category classification. Checked in order; the first
# matcher wins. Prefer slug lookups over service-name substring matches
# so two services with similar names don't both fall into Other.
CATEGORY_BY_SLUG: dict[str, str] = {
    # Email providers / gateways / deliverability
    "microsoft365": "Email",
    "google-workspace": "Email",
    "zoho": "Email",
    "protonmail": "Email",
    "proofpoint": "Email",
    "mimecast": "Email",
    "barracuda": "Email",
    "trendmicro": "Email",
    "symantec": "Email",
    "trellix": "Email",
    "cisco-ironport": "Email",
    "cisco-email": "Email",
    "sendgrid": "Email",
    "mailgun": "Email",
    "postmark": "Email",
    "sparkpost": "Email",
    "brevo": "Email",
    "mailchimp": "Email",
    "infobip": "Email",
    "aws-ses": "Email",
    "autospf": "Email",
    "ondmarc": "Email",
    "dmarcian": "Email",
    "easydmarc": "Email",
    "valimail": "Email",
    "agari": "Email",
    "proofpoint-efd": "Email",
    "uriports": "Email",
    "dmarc-advisor": "Email",
    "powerdmarc": "Email",
    "mimecast-dmarc-analyzer": "Email",
    # Identity
    "okta": "Identity",
    "entra-app-proxy": "Identity",
    "auth0": "Identity",
    "descope": "Identity",
    "onelogin": "Identity",
    # Additional identity providers
    "jumpcloud": "Identity",
    "aws-cognito": "Identity",
    "duo": "Identity",
    "ping-identity": "Identity",
    "cyberark": "Identity",
    "beyond-identity": "Identity",
    "1password": "Identity",
    "google-federated": "Identity",
    "google-managed": "Identity",
    "cisco-identity": "Identity",
    # Identity-hub slugs emitted by _detect_idp_hub when
    # shibboleth.example.edu / weblogin.example.edu / idp.example.edu
    # resolve. Signal that the org runs federated SSO.
    "federated-sso-hub": "Identity",
    "okta-sso-hub": "Identity",
    "adfs-sso-hub": "Identity",
    # Exchange on-prem / hybrid slug emitted by
    # _detect_exchange_onprem when owa./outlook./exchange.
    # subdomains resolve. Indicates self-hosted or hybrid
    # Exchange deployment rather than Exchange Online.
    "exchange-onprem": "Email",
    # Synthetic slug for orgs running their own mail infrastructure
    # (MX hosts under the queried apex or otherwise not matching any
    # recognized cloud / gateway fingerprint).
    "self-hosted-mail": "Email",
    # Cloud / Infrastructure
    "aws-route53": "Cloud",
    "aws-cloudfront": "Cloud",
    "aws-elb": "Cloud",
    "aws-s3": "Cloud",
    "aws-eb": "Cloud",
    "aws-acm": "Cloud",
    "azure-dns": "Cloud",
    "azure-cdn": "Cloud",
    "azure-appservice": "Cloud",
    "azure-fd": "Cloud",
    "azure-tm": "Cloud",
    "gcp-dns": "Cloud",
    "gcp-app": "Cloud",
    "cloudflare": "Cloud",
    "akamai": "Cloud",
    "fastly": "Cloud",
    "imperva": "Cloud",
    "reblaze": "Cloud",
    "indusface": "Cloud",
    "byteark": "Cloud",
    "claranet": "Cloud",
    "gamania-cloudforce": "Cloud",
    "turbify": "Cloud",
    "vercel": "Cloud",
    "netlify": "Cloud",
    "flyio": "Cloud",
    "railway": "Cloud",
    "render": "Cloud",
    "supabase": "Cloud",
    # Hosting-provider detection from A → PTR
    "aws-ec2": "Cloud",
    "aws-compute": "Cloud",
    "azure-vm": "Cloud",
    "gcp-compute": "Cloud",
    "linode": "Cloud",
    "digitalocean": "Cloud",
    "hetzner": "Cloud",
    "ovh": "Cloud",
    "vultr": "Cloud",
    "cdn77": "Cloud",
    "bunnycdn": "Cloud",
    # Cloud-vendor coverage additions (Cloud)
    "firebase-hosting": "Cloud",
    "gcp-cloud-functions": "Cloud",
    "firebase-realtime": "Cloud",
    "gcp-storage": "Cloud",
    "aws-amplify": "Cloud",
    "azure-blob": "Cloud",
    "azure-static-web-apps": "Cloud",
    "azure-container-apps": "Cloud",
    "azure-api-management": "Cloud",
    "oracle-cloud": "Cloud",
    "ibm-cloud": "Cloud",
    "alibaba-api": "Cloud",
    "alibaba-cdn": "Cloud",
    "alibaba-cloud": "Cloud",
    "replit": "Cloud",
    "glitch": "Cloud",
    # Security
    "crowdstrike": "Security",
    "sentinelone": "Security",
    "sophos": "Security",
    "knowbe4": "Security",
    "zscaler": "Security",
    "netskope": "Security",
    "paloalto": "Security",
    "cato": "Security",
    "wiz": "Security",
    "snyk": "Security",
    "github-advanced-security": "Security",
    "sonatype": "Security",
    "cosign-attestation": "Security",
    "lakera": "Security",
    # Cloud-vendor coverage additions (Security)
    "aws-waf": "Security",
    "cato-networks": "Security",
    "prisma-access": "Security",
    "letsencrypt": "Security",
    "digicert": "Security",
    "sectigo": "Security",
    "globalsign": "Security",
    "google-trust": "Security",
    # AI
    "openai": "AI",
    "anthropic": "AI",
    "mistral": "AI",
    "perplexity": "AI",
    "crewai-aid": "AI",
    "langsmith": "AI",
    "mcp-discovery": "AI",
    "dify": "AI",
    "n8n": "AI",
    "autogen": "AI",
    # Collaboration / Productivity
    "slack": "Collaboration",
    "notion": "Collaboration",
    "miro": "Collaboration",
    "atlassian": "Collaboration",
    "figma": "Collaboration",
    "dropbox": "Collaboration",
    "box": "Collaboration",
    "egnyte": "Collaboration",
    "clickup": "Collaboration",
    "asana": "Collaboration",
    "monday": "Collaboration",
    "loom": "Collaboration",
    "canva": "Collaboration",
    "zoom": "Collaboration",
    "airtable": "Collaboration",
    "github": "Collaboration",
    "gitlab": "Collaboration",
    "linear": "Collaboration",
    "disciple-media": "Collaboration",
    # Higher-ed LMS / SIS / student-facing platforms
    "canvas-lms": "Collaboration",
    "blackboard": "Collaboration",
    "moodle": "Collaboration",
    # Cloud-vendor coverage additions (Business Apps / Data)
    "oracle-fusion": "Business Apps",
    "looker-studio": "Data & Analytics",
    "ellucian-banner": "Business Apps",
    "handshake": "Business Apps",
    "tophat": "Collaboration",
    # Sales & marketing platforms missed in earlier passes
    "d365-marketing": "Business Apps",
    "sfmc": "Business Apps",
    "kartra": "Business Apps",
    "emma": "Email",
    "icontact": "Email",
    "mailerlite": "Email",
    # Infrastructure verification tokens (netlify already
    # mapped in Cloud above via the main fingerprint block; wpengine
    # is new; vmware-cloud is new)
    "wpengine": "Cloud",
    "vmware-cloud": "Cloud",
    # Nonprofit platforms
    "salesforce-npsp": "Business Apps",
    "blackbaud": "Business Apps",
    "classy": "Business Apps",
    # Surface-attribution slugs that should bucket as Cloud rather
    # than landing in the Business Apps fallback. AWS App Runner and
    # MuleSoft Anypoint are PaaS / iPaaS infrastructure; Cloudinary is a
    # media CDN; Apigee is an API gateway; AWS Global Accelerator is an
    # AWS networking service; Heroku and GitHub Pages are PaaS.
    "aws-app-runner": "Cloud",
    "aws-global-accelerator": "Cloud",
    "mulesoft": "Cloud",
    "cloudinary": "Cloud",
    "apigee": "Cloud",
    "cloudflare-pages": "Cloud",
    "github-pages": "Cloud",
    "heroku": "Cloud",
    "webflow": "Cloud",
    "sucuri": "Security",
    # Surface-attribution slugs that should bucket beyond Business Apps fallback.
    "intercom": "Collaboration",
    "submittable": "Collaboration",
    "pagerduty": "Security",
    "queue-it": "Security",
    "statuspage": "Collaboration",
    "betteruptime": "Collaboration",
    "bitly": "Business Apps",
    "shortio": "Business Apps",
    "unbounce": "Business Apps",
    "adobe-marketing": "Business Apps",
    "eloqua": "Business Apps",
    "pardot": "Business Apps",
    "wordpress-vip": "Cloud",
    "workos": "Identity",
    "beehiiv": "Business Apps",
    "docebo": "Collaboration",
    "skilljar": "Collaboration",
    "bizzabo": "Business Apps",
    "instatus": "Collaboration",
    "frontify": "Business Apps",
    "readme": "Collaboration",
    "swoogo": "Business Apps",
    "uptimerobot": "Collaboration",
    "uptimecom": "Collaboration",
    "ngrok": "Cloud",
    "blink": "Business Apps",
    "godaddy-email": "Email",
    "cloud-gov": "Cloud",
    "jobs2web": "Business Apps",
    "presspage": "Business Apps",
    "localist": "Collaboration",
    "rainfocus": "Business Apps",
    "aws-api-gateway": "Cloud",
    "aws-nlb": "Cloud",
    # Corpus run additions
    "paradox-ai": "Collaboration",
    "jibe": "Business Apps",
    "career-page": "Business Apps",
    "happydance": "Business Apps",
    "easyredir": "Business Apps",
    "gigya": "Identity",
    "f5-xc": "Cloud",
    "radware-cloud": "Security",
    "forgerock": "Identity",
    "ioriver": "Cloud",
    "section-io": "Cloud",
    "azion": "Cloud",
    "acquia": "Cloud",
    "pagely": "Cloud",
    "zuddl": "Business Apps",
    "postman-hosted": "Collaboration",
    "site24x7": "Collaboration",
    # Catalog growth from corpus-private/consolidated.txt scan.
    "akamai-eaa": "Security",
    "amplience": "Business Apps",
    "bigmarker": "Collaboration",
    "campuspress": "Collaboration",
    "certain-cvent": "Business Apps",
    "easydns": "Cloud",
    "edgetcdn-bitban": "Cloud",
    "edgio-cdn": "Cloud",
    "fanatics": "Business Apps",
    "fluid-topics": "Collaboration",
    "fortiweb-cloud": "Security",
    "framer": "Business Apps",
    "gandi-webredir": "Cloud",
    "gatsby-events": "Collaboration",
    "gitbook": "Collaboration",
    "hostinger-email": "Email",
    "ionos": "Cloud",
    "kinsta": "Cloud",
    "lumen-cdn": "Cloud",
    "medianova-cdn": "Cloud",
    "merlincdn": "Cloud",
    "mintlify": "Collaboration",
    "movable-ink": "Business Apps",
    "prowly": "Business Apps",
    "q4-ir": "Business Apps",
    "rackspace-email": "Email",
    "refined-site": "Collaboration",
    "sap-commerce": "Business Apps",
    "stova-aventri": "Collaboration",
    "talentera": "Business Apps",
    "terminus-sigstr": "Business Apps",
    "tistory": "Business Apps",
    "tumblr": "Business Apps",
    "uberflip": "Business Apps",
    "weglot": "Collaboration",
    "wordpress-com": "Business Apps",
    # Catalog growth from the 4270-apex real-corpus scan.
    # Without these mappings, panel display falls through to the
    # "Business Apps" default, which miscategorizes CDNs, analytics,
    # and security tooling.
    "250ok": "Email",
    "adobe-analytics": "Data & Analytics",
    "adobe-analytics-legacy": "Data & Analytics",
    "adobe-experience-cloud": "Data & Analytics",
    "arcgis-hub": "Data & Analytics",
    "aws-region-endpoint": "Cloud",
    "azion-cdn": "Cloud",
    "baidu-cdn": "Cloud",
    "bilibili-cdn": "Cloud",
    "blink-app": "Collaboration",
    "gooddata": "Data & Analytics",
    "jd-gslb": "Cloud",
    "microsoft-edge-cdn": "Cloud",
    "naver-cdn": "Cloud",
    "naver-cloud-platform": "Cloud",
    "ovs-cdn": "Cloud",
    "red-shield": "Security",
    "safebase": "Security",
    "socrata": "Data & Analytics",
    "taobao-cache": "Cloud",
    "tencent-edgeone": "Cloud",
    "tencent-wechat": "Collaboration",
    "vanta": "Security",
    "yahoo-japan-cdn": "Cloud",
    # Legacy slugs that the v1.9.x pipeline mis-bucketed
    # under "Business Apps" because they were never explicitly mapped.
    # Each one is unambiguous in the operator's mental model:
    # observability / data warehouses / product analytics belong in
    # Data & Analytics; MDM and privacy-management belong in Security;
    # standalone CDN and DNS providers belong in Cloud.
    "amplitude": "Data & Analytics",
    "databricks": "Data & Analytics",
    "datadog": "Data & Analytics",
    "dynatrace": "Data & Analytics",
    "grafana-cloud": "Data & Analytics",
    "heap": "Data & Analytics",
    "honeycomb": "Data & Analytics",
    "mixpanel": "Data & Analytics",
    "mongodb": "Data & Analytics",
    "newrelic": "Data & Analytics",
    "pendo": "Data & Analytics",
    "segment": "Data & Analytics",
    "sentry": "Data & Analytics",
    "snowflake": "Data & Analytics",
    "splunk": "Data & Analytics",
    "sumologic": "Data & Analytics",
    "hibp": "Security",
    "jamf": "Security",
    "kandji": "Security",
    "onetrust": "Security",
    "imgix": "Cloud",
    "keycdn": "Cloud",
    "ns1": "Cloud",
    "stackpath": "Cloud",
    "ultradns": "Cloud",
    # Slugs for cname_target rules discovered via the corpus
    # discovery loop. The marketing / generic-SaaS ones (substack, tally,
    # bynder, ...) roll up to Business Apps via the pass-2 fallback; only
    # the ones with a specific home are mapped here.
    "discourse": "Collaboration",
    "document360": "Collaboration",
    "statuspal": "Collaboration",
    "cloudsmith": "Cloud",
    "beyondtrust": "Identity",
    "janrain": "Identity",
    "arctic-wolf": "Security",
    "rootly": "Security",
    "material-security": "Email",
    "microsoft365-gov": "Email",
    # Slugs for TXT verification fingerprints discovered via the
    # corpus TXT-prefix mine. The generic / marketing ones roll up to
    # Business Apps via the fallback; only the ones with a specific home
    # are mapped here.
    "hackerone": "Security",
    "detectify": "Security",
    "bugcrowd": "Security",
    "spycloud": "Security",
    "validity": "Email",
    "lovable": "AI",
    "tollbit": "AI",
    "helpscout": "Collaboration",
    "censys": "Security",
    "confluent": "Data & Analytics",
    "datadome": "Security",
    "keybase": "Security",
    "windsurf": "AI",
    # NS-provider slugs from the signal mine (DNS / registrar
    # providers; excluded from the multi-cloud rollup below).
    "afternic": "Cloud",
    "csc": "Cloud",
    "dnsmadeeasy": "Cloud",
    "easydns2": "Cloud",
    "foundationdns": "Cloud",
    "gandi": "Cloud",
    "markmonitor": "Cloud",
    "worldnic": "Cloud",
    # TXT batch: explicit categories for non-Business-Apps slugs.
    "yahoo": "Email",
    "qqmail": "Email",
    "hashicorp-cloud": "Cloud",
    "stytch": "Identity",
    "identrust": "Identity",
    "jumio": "Identity",
    "specops": "Identity",
    "nordpass": "Identity",
    "wombat-security": "Security",
    "heyhack": "Security",
    "projectdiscovery": "Security",
    "abuseipdb": "Security",
    "safebreach": "Security",
    "virtru": "Security",
    "ethiack": "Security",
    "microsec": "Security",
    "securiti": "Security",
    "arcules": "Security",
    "fortinet": "Security",
    "deepl": "AI",
    "heygen": "AI",
    "kiro": "AI",
    "krisp": "AI",
    "fireflies": "AI",
    "read-ai": "AI",
    "feishu": "Collaboration",
    "happeo": "Collaboration",
    "lucidchart": "Collaboration",
    "invision": "Collaboration",
    # SPF batch: email-vendor slugs.
    "oracle-email-delivery": "Email",
    "powerspf": "Email",
    "elasticemail": "Email",
    "constantcontact": "Email",
    "spf-report": "Email",
    "messageprovider": "Email",
    "mailchannels": "Email",
    "stibee": "Email",
    "smtp-com": "Email",
    # MX batch: new MX-provider slugs.
    "mxrecord": "Email",
    "fastmail": "Email",
    "hornetsecurity": "Email",
    "appriver": "Email",
    "titanhq": "Security",
    "icloud-mail": "Email",
    "iberlayer": "Email",
    # DMARC rua batch: DMARC aggregate-report aggregators.
    "cloudflare-email-analytics": "Email",
    "cisa-dmarc": "Security",
    "sdmarc": "Email",
    "cp-dmarc": "Email",
    "emailanalyst": "Email",
    "redsift": "Email",
    "report-uri": "Security",
    "dmarc360": "Email",
    "mailhardener": "Email",
    "dmarc25": "Email",
    "inboxmonster": "Email",
    "dmarcinput": "Email",
    "glockapps": "Email",
    # NS batch: new DNS-provider slugs (categorized Cloud,
    # added to the rollup exclusions below since they are DNS operators,
    # not multi-cloud hosting vendors).
    "att-dns": "Cloud",
    "dnsimple": "Cloud",
    "f5-clouddns": "Cloud",
    "namebright": "Cloud",
    "etisalat-dns": "Cloud",
    "netnames": "Cloud",
    "constellix": "Cloud",
    "imperva-securedns": "Cloud",
    "easydns-org": "Cloud",
    "com-laude": "Cloud",
    "level3": "Cloud",
    "dnspod": "Cloud",
    # cname_target batch: vendor-specific terminal endpoints from
    # the corpus chain mine. Slugs with a non-Business-Apps home.
    "validity-everest": "Email",
    "adestra": "Email",
    "edgecast": "Cloud",
    "sap-cloud-kyma": "Cloud",
    "cloudways": "Cloud",
    "pressable": "Cloud",
    "sanity-cdn": "Cloud",
    "inap": "Cloud",
    "threatmetrix": "Security",
    "sourcepoint": "Security",
    "cirrus-identity": "Identity",
    "archbee": "Collaboration",
    "hund": "Collaboration",
    "redocly": "Collaboration",
    "zoomin": "Collaboration",
    # Catalog gap-fill from Phase F corpus output. Slugs with
    # a non-Business-Apps home.
    "readthedocs": "Collaboration",
    "stoplight": "Collaboration",
    "k15t-scroll-viewport": "Collaboration",
    "bevylabs": "Collaboration",
    "aptible": "Cloud",
    "platform-sh": "Cloud",
    "whecloud": "Cloud",
    "inxmail": "Email",
}

# Email service-name prefixes that bypass slug lookup. These catch
# DNS-derived service labels like "DMARC", "DKIM", "SPF: strict (-all)",
# "MTA-STS", "BIMI" which don't have a matching fingerprint slug.
EMAIL_SERVICE_PREFIXES: tuple[str, ...] = (
    "DMARC",
    "DKIM",
    "SPF",
    "MTA-STS",
    "BIMI",
    "TLS-RPT",
    "Exchange Autodiscover",  # M365 autodiscover infrastructure
    "Autodiscover",
)

# Service entries that are verification receipts,
# domain-ownership tokens, or registrar artefacts rather than deployed
# products. These get filtered out of the categorized Services block
# because showing "Google (site verified)" alongside "Google Workspace"
# reads as if the org uses two Google products when actually it's the
# same Search Console verification token counted twice.
FILTERED_SERVICE_SUFFIXES: tuple[str, ...] = (
    "(site verified)",
    "(domain verified)",
    "(verification)",
)
FILTERED_SERVICE_PREFIXES: tuple[str, ...] = (
    "Domain Connect",  # registrar handoff metadata, not a deployed product
)

# Qualifier map for Cloud-category services. Without
# this, "AWS Route 53" under "Cloud" reads as "primary cloud = AWS",
# which is almost always wrong — Route 53 is authoritative DNS, not
# compute. The qualifier makes the service type explicit so a CISO
# scanning the output can't accidentally confuse DNS hosting with a
# cloud compute / storage platform.
#
# Values:
#   "DNS"   — authoritative DNS hosting only
#   "CDN"   — content delivery / edge network
#   "WAF"   — web application firewall
#   "edge"  — edge compute / JAMstack platforms
CLOUD_SLUG_QUALIFIERS: dict[str, str] = {
    # DNS hosting
    "aws-route53": "DNS",
    "azure-dns": "DNS",
    "gcp-dns": "DNS",
    # CDN
    "aws-cloudfront": "CDN",
    "azure-cdn": "CDN",
    "akamai": "CDN",
    "fastly": "CDN",
    "cloudflare": "CDN",
    "cdn77": "CDN",
    "bunnycdn": "CDN",
    # WAF
    "imperva": "WAF",
    # Edge / serverless / JAMstack
    "vercel": "edge",
    "netlify": "edge",
    "flyio": "edge",
    "railway": "edge",
    "render": "edge",
    # Hosting provider detected via A → PTR reverse DNS.
    # The "(hosting)" qualifier disambiguates from CDN / DNS
    # entries so a CISO reading the Cloud row can tell at a glance
    # which services are delivering compute vs which are just
    # fronting traffic.
    "aws-ec2": "hosting",
    "aws-compute": "hosting",
    "azure-vm": "hosting",
    "gcp-compute": "hosting",
    "linode": "hosting",
    "digitalocean": "hosting",
    "hetzner": "hosting",
    "ovh": "hosting",
    "vultr": "hosting",
    # Non-DNS AWS / Azure / GCP — these ARE compute/storage so no suffix
    # (the raw name is enough — "AWS S3", "Azure App Service", …).
}

# Explicit display names for slugs whose
# corresponding fingerprint name is different, OR whose slug has no
# fingerprint entry at all. Without this, slugs like "google-managed"
# render as raw strings in the categorized services block.
SLUG_DISPLAY_OVERRIDES: dict[str, str] = {
    "google-managed": "Google Workspace (managed identity)",
    "google-federated": "Google Workspace (federated identity)",
    # Hosting-provider slugs emitted by dns._detect_hosting_from_a_record.
    # These come from A → PTR reverse-DNS matching, not from the
    # regular fingerprints.yaml pipeline, so there's no fingerprint
    # name to fall back to. Give them explicit user-facing names
    # here. The per-run region (e.g. "ca-central-1") is preserved
    # in the evidence record's raw_value, visible via --explain /
    # --json. The default panel shows the provider only, to keep
    # the Cloud row compact.
    "aws-ec2": "AWS EC2",
    "aws-compute": "AWS",
    "aws-elb": "AWS ELB",
    "azure-vm": "Azure VM",
    "gcp-compute": "GCP Compute Engine",
    "linode": "Linode",
    "digitalocean": "DigitalOcean",
    "hetzner": "Hetzner",
    "ovh": "OVH",
    "vultr": "Vultr",
    # Identity-hub slugs emitted by
    # dns._detect_idp_hub. These don't have fingerprint entries
    # so the raw slug would leak into the Identity row without
    # an explicit override.
    "federated-sso-hub": "SSO hub",
    "okta-sso-hub": "Okta SSO hub",
    "adfs-sso-hub": "ADFS SSO hub",
    # Exchange on-prem / hybrid slug emitted by
    # dns._detect_exchange_onprem. No fingerprint backs it,
    # the display override is how the Email-row entry gets a
    # human-readable name.
    "exchange-onprem": "Exchange Server (on-prem / hybrid)",
}

# Canonicalization from per-slug cloud entries to a single
# cloud-vendor identity. Used by the apex-level multi-cloud rollup
# indicator so that, for example, "AWS CloudFront" and "AWS Route 53"
# collapse to one AWS vote rather than counting as two distinct
# providers. The rollup answers "how many distinct cloud vendors does
# this organization's public footprint touch", not "how many cloud
# slugs fired"; the slug-level view stays available in the Cloud
# services row and the per-subdomain Subdomain row.
#
# Keys map to vendor labels operators recognise. Slugs absent from
# this map are not counted as cloud vendors at all, which is the
# right call for things like ``replit`` or ``glitch`` (developer
# platforms but not cloud vendors in the rollup sense). When a new
# cloud-categorized slug ships, add it here so the rollup sees it.
CLOUD_VENDOR_BY_SLUG: dict[str, str] = {
    # AWS family. Every AWS service slug rolls up to a single "AWS"
    # vote: an apex with Route 53, CloudFront, and S3 is one cloud
    # vendor (AWS), not three.
    "aws-route53": "AWS",
    "aws-cloudfront": "AWS",
    "aws-elb": "AWS",
    "aws-nlb": "AWS",
    "aws-s3": "AWS",
    "aws-eb": "AWS",
    "aws-acm": "AWS",
    "aws-ec2": "AWS",
    "aws-compute": "AWS",
    "aws-amplify": "AWS",
    "aws-api-gateway": "AWS",
    "aws-app-runner": "AWS",
    "aws-global-accelerator": "AWS",
    # Azure family
    "azure-dns": "Azure",
    "azure-cdn": "Azure",
    "azure-appservice": "Azure",
    "azure-fd": "Azure",
    "azure-tm": "Azure",
    "azure-vm": "Azure",
    "azure-blob": "Azure",
    "azure-static-web-apps": "Azure",
    "azure-container-apps": "Azure",
    "azure-api-management": "Azure",
    # GCP family. Firebase rolls up under GCP because Firebase is part
    # of the Google cloud footprint at the rollup level even though the
    # product brand is distinct. The Cloud services row still shows
    # "Firebase Hosting" as the slug name.
    "gcp-dns": "GCP",
    "gcp-app": "GCP",
    "gcp-compute": "GCP",
    "gcp-cloud-functions": "GCP",
    "gcp-storage": "GCP",
    "firebase-hosting": "GCP",
    "firebase-realtime": "GCP",
    # Alibaba family
    "alibaba-api": "Alibaba Cloud",
    "alibaba-cdn": "Alibaba Cloud",
    "alibaba-cloud": "Alibaba Cloud",
    # Standalone vendors. Each appears once because the slug already
    # names the vendor; no family collapse is needed.
    "cloudflare": "Cloudflare",
    "cloudflare-pages": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "imperva": "Imperva",
    "reblaze": "Reblaze",
    "indusface": "Indusface",
    "claranet": "Claranet",
    "cdn77": "CDN77",
    "bunnycdn": "BunnyCDN",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "flyio": "Fly.io",
    "railway": "Railway",
    "render": "Render",
    "supabase": "Supabase",
    "linode": "Linode",
    "digitalocean": "DigitalOcean",
    "hetzner": "Hetzner",
    "ovh": "OVH",
    "vultr": "Vultr",
    "oracle-cloud": "Oracle Cloud",
    "ibm-cloud": "IBM Cloud",
    "heroku": "Heroku",
    "vmware-cloud": "VMware Cloud",
    "cloud-gov": "Cloud.gov",
    "edgio-cdn": "Edgio",
    "lumen-cdn": "Lumen",
    "f5-xc": "F5 Distributed Cloud",
    # Additions from the 4270-apex real-corpus scan. Each
    # represents a cloud-vendor binding the operator would expect to
    # count in a multi-cloud summary.
    "aws-region-endpoint": "AWS",
    "microsoft-edge-cdn": "Azure",
    "naver-cloud-platform": "Naver Cloud Platform",
    "tencent-edgeone": "Tencent Cloud",
}

# Cloud-categorized slugs that are intentionally NOT counted
# as cloud vendors in the rollup. Two reasons a slug ends up here:
#
# (a) The product is SaaS hosting rather than cloud infrastructure
#     in the rollup sense. WP Engine, Kinsta, Pagely, Acquia, and
#     WordPress VIP host one specific application stack; counting
#     them as "cloud vendors" alongside AWS would dilute the
#     rollup's signal (a domain on AWS + WP Engine is not really
#     "multi-cloud" to an operator).
# (b) The product is a developer / prototyping platform rather than
#     a production cloud surface. Replit and Glitch fall here.
# (c) The product is a single-purpose specialty CDN or DAM that an
#     operator would not list alongside AWS / Azure / GCP when
#     describing a cloud footprint.
#
# This set is the single source of truth for those exclusions. The
# coverage-gap test (``tests/test_cloud_vendor_coverage.py``) asserts
# every Cloud-categorized slug is either in ``CLOUD_VENDOR_BY_SLUG``
# above or in this set, so a future contributor adding a new cloud
# slug to ``CATEGORY_BY_SLUG`` has to make the rollup decision
# explicitly. Silent omissions are not possible.
CLOUD_VENDOR_ROLLUP_EXCLUSIONS: frozenset[str] = frozenset(
    {
        # SaaS hosting — one application stack, not general cloud
        "wpengine",
        "kinsta",
        "pagely",
        "acquia",
        "wordpress-vip",
        "webflow",
        "github-pages",
        # Developer / prototyping platforms — not production cloud
        "replit",
        "glitch",
        # Ingress tunnel / developer preview platform, not general cloud
        "ngrok",
        # Package / artifact registry — distribution, not general cloud
        "cloudsmith",
        # DNS / registrar providers from the NS signal mine. DNS
        # operators, not multi-cloud hosting vendors for the panel summary.
        "afternic",
        "csc",
        "dnsmadeeasy",
        "easydns2",
        "foundationdns",
        "gandi",
        "markmonitor",
        "worldnic",
        # Specialty CDN / DAM — long-tail not in the rollup
        "cloudinary",
        "azion",
        "section-io",
        "ioriver",
        "medianova-cdn",
        # 2026-06 C2 corpus run: regional / specialty CDN and SMB shared
        # hosting. Same reasoning as azion / cloudinary (regional CDN) and
        # wpengine / kinsta (single-stack hosting): real vendors, but not
        # general multi-cloud footprint for the at-a-glance rollup. byteark
        # is aligned here for consistency with the convention.
        "byteark",
        "gamania-cloudforce",
        "turbify",
        "merlincdn",
        "edgetcdn-bitban",
        # Specialty hosting / DNS providers
        "ionos",
        "easydns",
        "gandi-webredir",
        # API management not tied to a major cloud at the rollup level
        "apigee",
        "mulesoft",
        # Additions: specialty / regional CDNs and partner-
        # integration markers where the chain does not by itself
        # establish a direct customer relationship with the vendor.
        "azion-cdn",
        "baidu-cdn",
        "bilibili-cdn",
        "jd-gslb",
        "naver-cdn",
        "ovs-cdn",
        "taobao-cache",
        "yahoo-japan-cdn",
        # Legacy specialty CDNs and standalone DNS providers — same
        # reasoning as the existing entries above (azion, cloudinary,
        # easydns). Operators do not list these alongside AWS/Azure/GCP
        # when describing a cloud footprint, but they are still
        # cloud-categorized for the panel display.
        "imgix",
        "keycdn",
        "ns1",
        "stackpath",
        "ultradns",
        # HashiCorp Cloud Platform is the SaaS-hosted control
        # plane for Terraform / Vault / Consul / Boundary , single-vendor
        # PaaS, not a general multi-cloud vendor for the panel rollup.
        "hashicorp-cloud",
        # NS batch: DNS-provider slugs from the NS signal mine.
        # DNS operators, not multi-cloud hosting vendors , same rationale
        # as the DNS/registrar block above.
        "att-dns",
        "dnsimple",
        "f5-clouddns",
        "namebright",
        "etisalat-dns",
        "netnames",
        "constellix",
        "imperva-securedns",
        "easydns-org",
        "com-laude",
        "level3",
        "dnspod",
        # cname_target batch: Cloud-categorized slugs that are
        # specialty SaaS-hosting / CDN / colo, not general multi-cloud
        # vendors. Same shape as wpengine / kinsta / pagely above.
        "edgecast",
        "sap-cloud-kyma",
        "cloudways",
        "pressable",
        "sanity-cdn",
        "inap",
        # Specialty PaaS / regional-CDN slugs from the Phase F
        # corpus output. Same rationale as the entries above.
        "aptible",
        "platform-sh",
        "whecloud",
    }
)

