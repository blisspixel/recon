# Weak areas — where recon looks thin, and why

recon is a passive, zero-credential tool. Its coverage ceiling is set by
what organizations publish in DNS and in unauthenticated identity /
certificate-transparency endpoints. Several common deployment shapes
publish very little of that — which means recon's output on those
domains will look sparse, and you should read it accordingly.

This page names the patterns and explains what to do instead of
over-interpreting the result.

## Heavy CDN / edge-proxied domains

Symptoms: `recon <domain>` shows CDN/WAF services (Cloudflare, Akamai,
Fastly, Imperva) but few others; the apex `CNAME` points at the CDN
edge; the insights section may say `Sparse public signal`.

Why: organizations that terminate everything at a CDN edge publish
minimal apex-level DNS. TXT verification tokens may be absent because
the org uses subdomain-scoped SaaS rather than apex-rooted integrations.

What to do: try the zone-apex of the subsidiary or product-specific
subdomains. CNAME breadcrumbs for M365 / Workspace are often visible
on `mail.` or `login.` prefixes. `recon chain <apex> --depth 2` walks
CNAME targets and surfaces related infrastructure.

## Chinese / APAC tech stacks

Symptoms: `recon <domain>` on `tencent.com`, `baidu.com`, `alibaba.com`
etc. shows `Self-hosted mail` as primary and little else matching the
built-in fingerprint catalog.

Why: domestic Chinese tech stacks use their own mail infrastructure
(`cloudmx.qq.com` for Tencent, `mx.baidu.com` for Baidu) and domestic
SaaS (DingTalk, WeCom, Aliyun services) that don't ship with
verifiable public DNS tokens the same way Western SaaS does.

What to do: take the `Self-hosted mail` + MX records as a signal
ceiling — these orgs are observably running their own stack, the
absence of Western-SaaS fingerprints is an accurate reading, not a
gap in recon's coverage.

## Regulated verticals behind web proxies

Symptoms: healthcare, financial services, or public-sector domains
show Cloudflare/Akamai + little else at the apex.

Why: compliance-driven architectures tend to terminate all external
traffic at a proxy layer and keep application infrastructure behind
it. Email is often routed through a gateway (Proofpoint, Mimecast,
Cisco IronPort), and the gateway's MX is the only mail-layer signal.

What to do: the gateway *is* the signal — recon's gateway inference
path (`likely primary provider via <Gateway>`) is doing the right
work. Don't read "few services" as "unsophisticated stack"; this
shape is common for enterprises that care about governance.

## Fully self-hosted / air-gapped shops

Symptoms: MX lands on the org's own apex (`mail.<domain>`), tenant ID
is absent, almost no SaaS fingerprints, `Unknown (no known provider
pattern matched)` on the provider line.

Why: orgs running their own mail servers and minimal cloud SaaS
deliberately leave a small passive footprint. recon is seeing the
ground truth — the footprint is thin because the infrastructure is
on-prem.

What to do: nothing. A sparse result on a genuinely self-hosted
domain is accurate, not a failure. The `Self-hosted mail` synthetic
slug is how recon names this shape now.

## Parked / dormant / portfolio apexes

Symptoms: no MX, no identity endpoints resolve, no tenant ID, no
SaaS services detected. Provider is `Unknown`.

Why: some apexes exist purely as a redirect or for legal / branding
reasons. There's no organization running against them — the domain
is parked.

What to do: check `related_domains` in the `--json` output; the
portfolio sibling apexes may be where the organization actually
lives. `recon batch portfolio.txt --json` correlates siblings via
shared verification tokens (see `clustering.py`).

## What "sparse" does NOT mean

- Not "recon is broken."
- Not "the org has an immature stack."
- Not "you should try harder / more aggressive scanning" —
  *aggressive scanning* is explicitly not this tool's job.

recon is bounded by what's passively observable in public DNS.
Sparse results are a real reading of a thin passive footprint.
They should inform, not frustrate.

## If you consistently get empty results on a domain class

That's signal about a coverage gap, not just a weak area. File an
issue with:

- The domain category (e.g. "European fintech", "Chinese CDN
  customers", "US higher-ed community colleges").
- A few representative apex domains.
- What records you can observe that *should* be diagnostic but recon
  ignores (e.g. specific `_dmarc` TXT receivers, specific MX gateway
  hosts).

That's how new fingerprints get proposed. See CONTRIBUTING.md for
the full fingerprint-PR workflow.
