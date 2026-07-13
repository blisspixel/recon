# Weak areas: where recon looks thin, and why

recon is a public-metadata-only, zero-credential tool. Its coverage ceiling is
set by what is visible in DNS, certificate transparency, unauthenticated
identity-discovery responses, and the documented MTA-STS and opt-in direct
probe boundaries. Several public-namespace shapes expose very little through
those channels, which means recon's output on those domains will look sparse,
and you should read it accordingly.

This page names the patterns and explains what to do instead of
over-interpreting the result.

See [correlation.md](correlation.md) for the correlation diagnostics shipped
across v1.7-v1.9, their evidence limits, and the product benchmark that must
establish whether they add operator value beyond simpler observations.

## Heavy CDN / edge-proxied domains

Symptoms: `recon <domain>` shows CDN/WAF services (Cloudflare, Akamai,
Fastly, Imperva) but few others; the apex `CNAME` points at the CDN
edge; the insights section may say `Sparse public signal`.

Why: an observed CDN edge can hide the application or origin behind it. Sparse
apex TXT data is compatible with subdomain-scoped integrations, an intentionally
small public namespace, stale or incomplete collection, or services that publish
no detectable record. Public metadata does not identify which explanation is
correct.

What to do: keep intentional scope operator-supplied. Query another supplied
apex separately, or pass `--exact` when the operator specifically wants one
literal subhost. To inspect bounded public breadcrumbs from the current query
coordinate, `recon <apex> --chain --depth 2` follows CNAME and certificate-
transparency relationships. Those results describe observed namespace
structure, not subsidiaries or ownership; see the wildcard SAN sibling and
chain motif sections of [correlation.md](correlation.md).

## Unclassified CNAME chain termini

Symptoms: the panel shows `Unclassified surface`, or `--json
--include-unclassified` includes `unclassified_cname_chains`, but the
Services list does not name the SaaS or infrastructure vendor behind those
chains.

Why: recon reached a public CNAME chain terminus, but no built-in
`cname_target` fingerprint matched it. That terminus is evidence that a public
DNS relationship exists; it is not enough by itself to claim a specific vendor
when the catalog does not recognize the suffix. Shared CDN hostnames,
customer-specific vanity hosts, same-zone or brand-similar routing names, and
newly observed SaaS edges can all look similar at this layer.

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

Why: the built-in catalog has less coverage for some regional providers and
localized verification schemes. An MX host inside the queried namespace or an
unmatched domestic-provider pattern can therefore reach the compatibility label
`Self-hosted mail`. That label does not establish who operates the mail system
or where it runs.

What to do: report the observed MX route and the unmatched-provider ceiling.
Treat absent Western-SaaS fingerprints as unresolved, not as evidence that the
namespace uses an in-house stack. Repeated unmatched public patterns are catalog
quality candidates, subject to the contribution and data-handling rules.

## Regulated verticals behind web proxies

Symptoms: healthcare, financial services, or public-sector domains
show Cloudflare/Akamai + little else at the apex.

Why: a proxy or gateway can be the only public routing layer visible from DNS.
The same shape is compatible with many operational and organizational causes;
public configuration does not establish that compliance, governance, or any
other cause produced it.

What to do: report the observed edge or gateway and its evidence role. An MX
gateway is a delivery-path observation, not proof of the downstream mailbox
provider. Do not turn a thin service list into either a maturity criticism or a
governance claim.

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

## Same-namespace or unattributed mail routing

Symptoms: MX lands under the queried namespace (`mail.<domain>`), tenant ID
is absent, almost no SaaS fingerprints, `Unknown (no known provider
pattern matched)` on the provider line.

Why: `Self-hosted mail` is a compatibility label for an MX route under the
queried namespace when no known provider pattern establishes a stronger
attribution. It does not prove that the host is live, operated by the domain
owner, physically on premises, or part of an air-gapped environment.

What to do: report the MX hostname and the unmatched-provider observation. A
sparse result is valid as a statement about collected public evidence, while
the underlying deployment remains unresolved.

## Sparse or apparently dormant apexes

Symptoms: no MX, no identity endpoints resolve, no tenant ID, no
SaaS services detected. Provider is `Unknown`.

Why: this shape is compatible with a parked or dormant name, a redirect-only
namespace, an intentionally sparse configuration, or a collection gap. recon
does not observe enough to choose among those explanations or to decide whether
an organization operates behind the apex.

What to do: check `related_domains` in `--json` as bounded CNAME, CT, or
autodiscover breadcrumbs, not as portfolio or ownership facts. When an operator
already supplies a related set, `recon batch portfolio.txt --json` can report
exact shared verification-token strings. Token reuse does not establish that
the domains are siblings, share an owner, or are currently administered
together.

## What "sparse" does NOT mean

- Not "recon is broken."
- Not "the org has an immature stack."
- Not "you should try harder / more aggressive scanning";
  *aggressive scanning* is explicitly not this tool's job.

recon is bounded by its documented public-metadata sources and collection
opportunities. Sparse results are a real reading of the evidence that those
bounded channels returned, not a conclusion about the organization or systems
behind a domain.
They should inform, not frustrate.

## If you consistently get empty results on a domain class

That's signal about a coverage gap, not just a weak area. File an
issue with:

- The domain category (e.g. "European fintech", "Chinese CDN
  customers", "US higher-ed community colleges").
- A fictionalized or aggregate description of the affected namespace shape;
  do not put real target apexes in a public issue.
- What records you can observe that *should* be diagnostic but recon
  ignores (e.g. specific `_dmarc` TXT receivers, specific MX gateway
  hosts).

That's how new fingerprints get proposed. See CONTRIBUTING.md for
the full fingerprint-PR workflow.
