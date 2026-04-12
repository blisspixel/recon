# Legal

## Disclaimer

This tool queries publicly available DNS records and unauthenticated HTTP endpoints (Microsoft OIDC discovery, GetUserRealm, Google Workspace, crt.sh certificate transparency logs). It does not attempt to authenticate, exploit vulnerabilities, bypass access controls, or access any non-public data. There is no active scanning, no brute-forcing, and no interaction with target systems beyond reading their published DNS records and querying public discovery endpoints.

Every piece of information this tool returns is already available to anyone running `dig`, `nslookup`, or visiting the same public endpoints in a browser. The tool simply automates the collection and adds interpretation. If an organization's security depends on this information not being looked at, that's security by obscurity — the records are public by design.

This tool is intended for legitimate purposes such as:

- Pre-sales research and proposal preparation
- IT architecture assessment and planning
- Email security posture review
- Vendor and partner due diligence

You are responsible for ensuring your use complies with all applicable laws, regulations, and terms of service in your jurisdiction. The authors are not responsible for how this tool is used.

This tool is not designed for, and should not be used for, unauthorized access, competitive intelligence gathering that violates applicable law, harassment, or any purpose that would violate the terms of service of the queried endpoints.

## Accuracy

Output is derived from public DNS records and unauthenticated endpoints. It may be incomplete, outdated, or incorrect. Do not make business decisions based solely on this tool's output without independent verification.

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
- Acquisition target assessment based on public configuration data

All tool output uses neutral, factual language describing what is publicly observable. Output is not intended to facilitate unauthorized access, offensive security operations, or any activity that would violate applicable law or terms of service.

The Posture Score (0–100) and Hardening Gap outputs are based on publicly observable controls such as DNS records, DMARC policies, and MTA-STS configuration. They do not constitute a comprehensive security audit, security rating, or certification. Organizations may have additional security controls that are not publicly visible and therefore not reflected in these assessments.
