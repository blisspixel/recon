# Cloudflare fingerprint review

Date: 2026-08-30 UTC

Status: complete; eight rules dated from current first-party evidence, one
unsupported generic matcher removed, and one legacy China partner rule retained
undated with a narrower claim.

## Scope

This review covers the built-in Cloudflare DNS, partial-zone edge, China
Network, and Pages CNAME observations. It checks the exact DNS shape and the
role recon assigns to each match. Cloudflare Email Service and DMARC Management
use separate slugs and are outside this pass.

Collection boundary: current public Cloudflare documentation only. No target
domain was queried, and no corpus row, credential, paid source, or direct probe
was used.

## Dispositions

| Type and pattern | Current first-party evidence | Decision | Claim boundary |
|---|---|---|---|
| Subdomain TXT `cloudflare-verify:.` | The current [partial-zone setup guide](https://developers.cloudflare.com/dns/zone-setups/partial-setup/setup/) directs operators to publish a value at `cloudflare-verify.<domain>` and retain it while the CNAME setup remains active. | Replace the unsupported apex value matcher `^cloudflare-verify=` with the owner-qualified form and date it. | Zone-binding observation only. Do not infer the account operator, active traffic, or enabled edge features. |
| NS `ns.cloudflare.com` | The current [nameserver guide](https://developers.cloudflare.com/dns/nameservers/) names standard `*.ns.cloudflare.com` authoritative nameservers. | Narrow the broad `cloudflare.com` suffix to this documented family and date it. | Authoritative DNS only. Do not infer proxying, caching, WAF, or other application services. |
| NS `secondary.cloudflare.com` | The same current guide names `*.secondary.cloudflare.com` for secondary authoritative DNS. | Add and date this separate documented family. | Secondary authoritative DNS only. Do not infer other Cloudflare product roles. |
| CNAME `cdn.cloudflare.net` | The current [partial-zone setup guide](https://developers.cloudflare.com/dns/zone-setups/partial-setup/setup/) requires `{hostname}.cdn.cloudflare.net` targets for proxied hostnames. | Replace the string-fragment matcher `cloudflare` with the documented DNS suffix and date it. | A reverse-proxy route only. Do not infer feature set or current traffic. |
| CNAME target `cdn.cloudflare.net` | The same current guide names the exact target family for each proxied partial-zone hostname. | Narrow the broad `cloudflare.net` rule to `cdn.cloudflare.net` and date it. | A reverse-proxy route only. |
| CNAME target `cdn.cloudflareanycast.net` | The current [China Authoritative DNS guide](https://developers.cloudflare.com/china-network/concepts/china-dns/) names this family for the global-default partial-zone route. | Add and date the exact current family. | China Network configuration relationship only. Do not infer traffic or enabled features. |
| CNAME target `cdn.cloudflarecn.net` | The same China Network guide names this family for the in-China partial-zone route. | Add and date the exact current family. | China Network configuration relationship only. Do not infer traffic or enabled features. |
| CNAME target `pacloudflare.com` | No current first-party page reviewed in this pass names this exact family. Current guidance names the two `cdn.cloudflare*` families above. | Retain the existing observation undated and remove the current-state claim. | Legacy provider-domain observation only. |
| CNAME target `pages.dev` | The current [Pages custom-domain guide](https://developers.cloudflare.com/pages/configuration/custom-domains/) directs custom subdomains to `<project>.pages.dev`. | Retain, narrow, and date the rule. | Pages deployment binding only. Do not infer current publication or reachability. |

The already dated `cloudflare_dashboard_sso=` token remains unchanged. This
pass does not treat a provider-controlled hostname as evidence of account
ownership, current traffic, a product plan, or a specific security feature.

## Precision and reproducibility

`tests/test_cloudflare_fingerprints.py` pins:

- exact references, review dates, and bounded descriptions for all eight
  currently supported rules;
- exact owner-qualified TXT matching, including rejection of the retired apex
  value, lookalike owners, and empty values;
- replacement of the generic CNAME string matcher with a DNS-label-bounded
  target;
- positive and deceptive-suffix-negative coverage for global, China Network,
  and Pages CNAME targets;
- removal of the broad `cloudflare.net` classification for unrelated provider
  hostnames; and
- the empty reference and undated disposition for `pacloudflare.com`.

The generated catalog contains 869 entries, 692 unique slugs, and 1,112
detections. Of those detections, 157 are dated (14.1 percent), and none of the
dated rules is stale at the 365-day threshold.
