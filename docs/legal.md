# Legal

## Disclaimer

This tool queries publicly available DNS records and unauthenticated HTTP endpoints. It does not attempt to authenticate, bypass access controls, or access any non-public data. There is no active scanning, no brute-forcing, and no direct interaction with the queried domain's servers beyond reading their published DNS records and querying public discovery endpoints. No accounts, API keys, or credentials are required — ever.

Every piece of information this tool returns is already available to anyone running `dig`, `nslookup`, or visiting the same public endpoints in a browser. The tool simply automates the collection and adds interpretation.

This tool is intended for legitimate purposes such as:

- Pre-sales research and proposal preparation
- IT architecture assessment and planning
- Email security posture review
- Vendor and partner due diligence

## What sees your queries

The queried domain's servers never receive a packet from this tool. However, the intermediary services that the tool queries will see your IP address in their access logs:

| Service queried | What it sees | Who operates it |
|---|---|---|
| Your DNS resolver | Every DNS query (TXT, MX, CNAME, etc.) for the queried domain | Your ISP, or whichever resolver you configured (e.g., 8.8.8.8, 1.1.1.1) |
| `login.microsoftonline.com` | OIDC discovery + GetUserRealm requests for the queried domain | Microsoft |
| `accounts.google.com` | Google Workspace identity routing probe for the queried domain | Google |
| `crt.sh` | Certificate transparency search for the queried domain | Sectigo (community service) |
| `api.certspotter.com` (fallback) | Certificate transparency search, only when crt.sh is unavailable | SSLMate |
| `cse.{domain}` | Google Workspace CSE configuration probe | Google (via the domain's subdomain) |
| `mta-sts.{domain}` | MTA-STS policy file fetch | Hosted by the domain owner (this is the one exception — it's a direct HTTPS GET to a domain-controlled subdomain, but the endpoint is a public standard designed for external consumption) |

The queried domain itself only appears as a parameter in queries to third-party services. The only direct contact with domain-controlled infrastructure is the MTA-STS policy fetch (`https://mta-sts.{domain}/.well-known/mta-sts.txt`), which is a publicly documented, standards-compliant endpoint designed for external consumption.

You are responsible for ensuring your use complies with all applicable laws, regulations, and terms of service in your jurisdiction. The authors are not responsible for how this tool is used.

This tool is not designed for, and should not be used for, unauthorized access, competitive intelligence gathering that violates applicable law, harassment, or any purpose that would violate the terms of service of the queried endpoints.

## Accuracy

Output is derived from public DNS records and unauthenticated endpoints. It may be incomplete, outdated, or incorrect. Do not make business decisions based solely on this tool's output without independent verification.

DNS records are self-reported metadata. Organizations may leave stale records from previous configurations, and sophisticated actors could intentionally publish misleading information. All output should be treated as observed indicators, not confirmed facts. The tool's dual confidence model, per-detection corroboration scoring, and evidence traceability are designed to surface uncertainty — but no passive tool can guarantee the accuracy of self-reported public data.

## Fictional Examples

All company names, tenant IDs, and domains used in the README, the `examples/` folder, and test fixtures are fictional. They use [Microsoft's standard sample company names](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges) (Contoso, Northwind Traders, Fabrikam, etc.) or clearly fabricated identifiers. The README example is based on the structure and density of a real Fortune 500 lookup, with all identifying details replaced. No real company is depicted. Any resemblance to real organizations is coincidental.

## Third-Party Services

This tool queries endpoints operated by Microsoft, Google, and public DNS infrastructure. It is not affiliated with, endorsed by, or sponsored by any of these companies. Product names mentioned in fingerprint definitions are trademarks of their respective owners.

## Defensive Security Assessment Tools

The `assess_exposure`, `find_hardening_gaps`, and `compare_postures` tools synthesize existing pipeline data into structured security posture views. These tools operate exclusively on data already collected by the standard domain resolution pipeline — they perform zero additional network calls, query no new endpoints, and require no credentials beyond what the base tool uses.

These tools are intended for the following legitimate use cases:

- Defensive security review and posture assessment
- Vendor and partner due diligence
- Security architecture planning and gap analysis
- Peer benchmarking of publicly observable security controls
- Acquisition assessment based on public configuration data

All tool output uses neutral, factual language describing what is publicly observable. Output is not intended to facilitate unauthorized access, offensive security operations, or any activity that would violate applicable law or terms of service.

The Posture Score (0–100) and Hardening Gap outputs are based on publicly observable controls such as DNS records, DMARC policies, and MTA-STS configuration. They do not constitute a comprehensive security audit, security rating, or certification. Organizations may have additional security controls that are not publicly visible and therefore not reflected in these assessments.
