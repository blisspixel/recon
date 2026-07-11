"""Slug name and classification tables for the result merger.

Pure data — gateway/provider slug sets and the humanizing name maps — split out
of merger.py so the merge logic stays under the file-size cap. No logic, no
imports beyond annotations. `recon_tool.merger` re-exports each table under its
historical ``_NAME`` alias so internal callers and tests are unchanged.
"""

from __future__ import annotations

# Variant-to-product relationships shared by display deduplication and
# claim-level confidence scoring. The scoring layer deliberately excludes
# google-site because site verification alone does not establish Workspace.
VARIANT_SLUG_PARENTS: dict[str, str] = {
    "google-managed": "google-workspace",
    "google-federated": "google-workspace",
    "google-site": "google-workspace",
    "google-workspace-modules": "google-workspace",
}

# Gateway slugs — MX-detected slugs that represent email security gateways
# rather than primary email providers. Shared with insights.py.
GATEWAY_SLUGS: frozenset[str] = frozenset(
    {
        "proofpoint",
        "mimecast",
        "barracuda",
        "cisco-ironport",
        "cisco-email",
        "symantec",
        "trellix",
        "trendmicro",
    }
)

# Provider slugs that can be primary email providers (MX-based)
EMAIL_PROVIDER_SLUG_NAMES: dict[str, str] = {
    "microsoft365": "Microsoft 365",
    "google-workspace": "Google Workspace",
    "zoho": "Zoho Mail",
    "protonmail": "ProtonMail",
    "aws-ses": "AWS SES",
    # Compatibility slug for MX hosts that do not match the catalog. Their
    # operator and hosting model are unknown, so the label stays unclassified.
    "self-hosted-mail": "Custom or unclassified MX",
}

GATEWAY_SLUG_NAMES: dict[str, str] = {
    "proofpoint": "Proofpoint",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "cisco-ironport": "Cisco IronPort",
    "cisco-email": "Cisco Secure Email",
    "symantec": "Symantec/Broadcom",
    "trellix": "Trellix (FireEye)",
    "trendmicro": "Trend Micro",
}


# Non-MX evidence source types that carry signal about the downstream email
# provider even when MX points to a gateway. Ordered by strength of signal.
PROVIDER_INFERENCE_SOURCES: frozenset[str] = frozenset(
    {
        "TXT",  # SPF includes, site-verification tokens
        "DKIM",  # google._domainkey, selector1._domainkey
        "HTTP",  # Google identity endpoint responses, Microsoft OIDC
        "OIDC",  # Microsoft OIDC discovery
        "USERREALM",  # Microsoft GetUserRealm
    }
)

# Mapping from slug to the display name used when inferring a likely
# downstream email provider from non-MX evidence. Must be a subset of the
# strict provider map so the two stay consistent when both fire.
LIKELY_PROVIDER_SLUG_NAMES: dict[str, str] = {
    "microsoft365": "Microsoft 365",
    "google-workspace": "Google Workspace",
    "zoho": "Zoho Mail",
    "protonmail": "ProtonMail",
}


# Humanize raw slugs for insight text. Without this, insight
# strings leak identifiers like "google-managed", "crewai-aid",
# "cosign-attestation" that read as developer jargon to users. Map
# known technical slugs to user-friendly display names; everything
# else falls back to a title-cased version of the slug with dashes
# replaced by spaces.
SLUG_HUMAN_NAMES: dict[str, str] = {
    "microsoft365": "Microsoft 365",
    "google-workspace": "Google Workspace",
    "google-federated": "Google Workspace (federated)",
    "google-managed": "Google Workspace (managed)",
    "google-site": "Google Search Console",
    "google-trust": "Google Trust Services",
    "google-workspace-modules": "Google Workspace modules",
    "google-cse": "Google Workspace CSE",
    "aws-ses": "AWS SES",
    "aws-route53": "Route 53",
    "aws-cloudfront": "CloudFront",
    "aws-s3": "S3",
    "aws-elb": "ELB",
    "aws-eb": "Elastic Beanstalk",
    "aws-acm": "AWS ACM",
    "azure-dns": "Azure DNS",
    "azure-appservice": "Azure App Service",
    "azure-cdn": "Azure CDN",
    "azure-fd": "Azure Front Door",
    "azure-tm": "Azure Traffic Manager",
    "gcp-dns": "GCP Cloud DNS",
    "gcp-app": "GCP App Engine",
    "mta-sts-enforce": "MTA-STS enforce",
    "mta-sts-testing": "MTA-STS testing",
    "tls-rpt": "TLS-RPT",
    "proofpoint-efd": "Proofpoint EFD",
    "dmarc-advisor": "DMARC Advisor",
    "mimecast-dmarc-analyzer": "Mimecast DMARC Analyzer",
    "1password": "1Password",
    "ping-identity": "Ping Identity",
    "beyond-identity": "Beyond Identity",
    "github-advanced-security": "GitHub Advanced Security",
    "cosign-attestation": "Cosign attestation",
    "crewai-aid": "CrewAI",
    "mcp-discovery": "MCP discovery",
    "langsmith": "LangSmith",
    "cisco-ironport": "Cisco IronPort",
    "cisco-email": "Cisco Secure Email",
    "cisco-identity": "Cisco Identity",
    "knowbe4": "KnowBe4",
    "sentinelone": "SentinelOne",
    "crowdstrike": "CrowdStrike",
    "paloalto": "Palo Alto",
    "letsencrypt": "Let's Encrypt",
    # Proper-case brand names so insight text
    # doesn't title-case them into wrong forms like "Sendgrid" or
    # "Cloudflare" when they have distinctive casing.
    "sendgrid": "SendGrid",
    "mailgun": "Mailgun",
    "mailchimp": "Mailchimp",
    "postmark": "Postmark",
    "sparkpost": "SparkPost",
    "brevo": "Brevo",
    "protonmail": "ProtonMail",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "onelogin": "OneLogin",
    "auth0": "Auth0",
    "descope": "Descope",
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "mistral": "Mistral",
    "perplexity": "Perplexity",
    "autospf": "AutoSPF",
    "ondmarc": "OnDMARC (Red Sift)",
    "dmarcian": "dmarcian",
    "easydmarc": "EasyDMARC",
    "valimail": "Valimail",
    "uriports": "URIports",
    "powerdmarc": "PowerDMARC",
    "agari": "Agari",
    "lakera": "Lakera",
    "cyberark": "CyberArk",
    "okta": "Okta",
    "auth": "Auth0",
    "duo": "Duo Security",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "flyio": "Fly.io",
    "railway": "Railway",
    "github": "GitHub",
    "gitlab": "GitLab",
    "atlassian": "Atlassian",
    "slack": "Slack",
    "notion": "Notion",
    "figma": "Figma",
    "miro": "Miro",
    "dropbox": "Dropbox",
    "zoom": "Zoom",
    "disciple-media": "Disciple Media",
    "kartra": "Kartra",
    "salesforce": "Salesforce",
    "salesforce-mc": "Salesforce Marketing Cloud",
    "hubspot": "HubSpot",
    "servicenow": "ServiceNow",
    "docusign": "DocuSign",
    "imperva": "Imperva",
    "wiz": "Wiz",
    "snyk": "Snyk",
    "zscaler": "Zscaler",
    "netskope": "Netskope",
    "proofpoint": "Proofpoint",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "sophos": "Sophos",
    "sectigo": "Sectigo",
    "digicert": "DigiCert",
    "globalsign": "GlobalSign",
    "trendmicro": "Trend Micro",
    "trellix": "Trellix",
    "symantec": "Symantec",
}


# Known short acronyms that should stay uppercase in the slug
# fallback. This is intentionally narrow — random 2-3 char words
# like "new" or "old" should title-case, not shout.
SLUG_ACRONYMS: frozenset[str] = frozenset(
    {"sso", "idp", "waf", "mfa", "cdn", "dns", "vpn", "mdm", "iam", "api", "cse", "pki"}
)
