# Weak areas: where recon looks thin, and why

recon is a passive, zero-credential tool. Its coverage ceiling is set by
what organizations publish in DNS and in unauthenticated identity /
certificate-transparency endpoints. Several common deployment shapes
publish very little of that, which means recon's output on those
domains will look sparse, and you should read it accordingly.

This page names the patterns and explains what to do instead of
over-interpreting the result.

See [correlation.md](correlation.md) for the correlation extensions
(shipped v1.7-v1.9) that recover usable signal even on these weak-area
shapes.

## Heavy CDN / edge-proxied domains

Symptoms: `recon <domain>` shows CDN/WAF services (Cloudflare, Akamai,
Fastly, Imperva) but few others; the apex `CNAME` points at the CDN
edge; the insights section may say `Sparse public signal`.

Why: organizations that terminate everything at a CDN edge publish
minimal apex-level DNS. TXT verification tokens may be absent because
the org uses subdomain-scoped SaaS rather than apex-rooted integrations.

What to do: try the zone-apex of the subsidiary or product-specific
subdomains. CNAME breadcrumbs for M365 / Workspace are often visible
on `mail.` or `login.` prefixes. `recon <apex> --chain --depth 2` walks
CNAME targets and surfaces related infrastructure, as described in the
wildcard SAN sibling and chain motif sections of
[correlation.md](correlation.md).

## Unclassified CNAME chain termini

Symptoms: the panel shows `Unclassified surface`, or `--json
--include-unclassified` includes `unclassified_cname_chains`, but the
Services list does not name the SaaS or infrastructure vendor behind those
chains.

Why: recon reached a public CNAME chain terminus, but no built-in
`cname_target` fingerprint matched it. That terminus is evidence that a public
DNS relationship exists; it is not enough by itself to claim a specific vendor
when the catalog does not recognize the suffix. Shared CDN hostnames,
customer-specific vanity hosts, intra-org routing names, and newly observed
SaaS edges can all look similar at this layer.

What to do: use `recon discover <domain>` or inspect
`unclassified_cname_chains` from `--include-unclassified` as a fingerprint
proposal queue. Before adding a `cname_target` rule, confirm the suffix against
public vendor docs or repeated validation evidence, add negative tests, and keep
the wording hedged. Do not turn a bare unknown terminus into a broad service
claim.

Maintainer-local corpus candidates follow the stricter active plan in
[c3-ct-validation-plan.md](c3-ct-validation-plan.md): private rows stay private,
public docs or aggregate-safe evidence justify any promoted rule, and every new
suffix rule gets a lookalike negative test.

## Wildcard-heavy DNS zones

Symptoms: many guessed prefixes resolve, but the services list stays thin or
looks repetitive. Related domains may include generic names that all point to
the same edge.

Why: wildcard DNS makes every prefix appear valid, including names that are
not actual services. A passive tool cannot safely distinguish all wildcard
responses from intentionally configured subdomains without active HTTP checks.

What to do: trust CNAME/TXT/MX evidence more than the presence of a resolving
subdomain name. If you contribute fingerprints, never rely on a generic
subdomain label alone, as described in the wildcard SAN sibling and chain
motif sections of [correlation.md](correlation.md).

## Chinese / APAC tech stacks

Symptoms: large domestic-Chinese and some APAC apexes commonly show
`Self-hosted mail` as primary with little else matching the built-in
fingerprint catalog.

Why: these stacks use in-house mail infrastructure (provider-hosted
domestic MX patterns) and domestic SaaS (DingTalk, WeCom, Aliyun
services) that don't publish verifiable public DNS tokens the same
way Western SaaS does.

What to do: take the `Self-hosted mail` + MX records as a signal
ceiling. These orgs are observably running their own stack, and the
absence of Western-SaaS fingerprints is an accurate reading, not a
gap in recon's coverage.

## Regulated verticals behind web proxies

Symptoms: healthcare, financial services, or public-sector domains
show Cloudflare/Akamai + little else at the apex.

Why: compliance-driven architectures tend to terminate all external
traffic at a proxy layer and keep application infrastructure behind
it. Email is often routed through a gateway (Proofpoint, Mimecast,
Cisco IronPort), and the gateway's MX is the only mail-layer signal.

What to do: the gateway *is* the signal. recon's gateway inference
path (`likely primary provider via <Gateway>`) is doing the right
work. Don't read "few services" as "unsophisticated stack"; this
shape is common for enterprises that care about governance.

## Custom DKIM selectors and branded email senders

Symptoms: the email section shows `No DKIM observed` or a lower email
security score even though the domain publishes DMARC, SPF, MTA-STS,
or a known mail gateway.

Why: DKIM selectors are not enumerable from DNS. recon probes common
selectors and known provider patterns, but many senders use per-tenant
or branded selectors that are only visible if you already know the
selector name. A missing DKIM match therefore means "not observed at
the probed selectors," not "DKIM is absent."

What to do: use `--explain` to see which selectors and records were
actually observed. A commercial gateway plus enforcing DMARC does not
establish DKIM, so recon does not credit it as a substitute for an observed
selector.
If you contribute a DKIM fingerprint, keep it provider-specific and
anchored to a stable public selector pattern; do not add broad
selector guesses.

## Fully self-hosted / air-gapped shops

Symptoms: MX lands on the org's own apex (`mail.<domain>`), tenant ID
is absent, almost no SaaS fingerprints, `Unknown (no known provider
pattern matched)` on the provider line.

Why: orgs running their own mail servers and minimal cloud SaaS
deliberately leave a small passive footprint. recon is seeing the
ground truth: the footprint is thin because the infrastructure is
on-prem.

What to do: nothing. A sparse result on a genuinely self-hosted
domain is accurate, not a failure. The `Self-hosted mail` synthetic
slug is how recon names this shape now.

## Parked / dormant / portfolio apexes

Symptoms: no MX, no identity endpoints resolve, no tenant ID, no
SaaS services detected. Provider is `Unknown`.

Why: some apexes exist purely as a redirect or for legal / branding
reasons. There's no organization running against them; the domain
is parked.

What to do: check `related_domains` in the `--json` output; the
portfolio sibling apexes may be where the organization actually
lives. `recon batch portfolio.txt --json` correlates siblings via
shared verification tokens (see `clustering.py`).

## What "sparse" does NOT mean

- Not "recon is broken."
- Not "the org has an immature stack."
- Not "you should try harder / more aggressive scanning";
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
