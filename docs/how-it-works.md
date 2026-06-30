# How recon Works

This is the plain-language model overview. For the formal math and prior art,
read [correlation.md](correlation.md). For runtime caps and exact exit codes,
read [operational-contract.md](operational-contract.md).

## The Core Claim

recon answers one narrow question:

What does the public channel reveal about this domain's external technology
stack and identity posture?

The answer is a hedged observation with provenance, not a security verdict. The
tool can say "DMARC policy is `p=none`" or "Microsoft 365 tenant indicators
observed." It should not say "this organization is secure" or "this control is
exploitable."

## Inputs

recon collects from three public source families:

| Source | Examples | What it can reveal |
|---|---|---|
| DNS | MX, TXT, SPF, DMARC, DKIM, BIMI, CNAME, NS, SRV, CAA | Email providers, gateways, SaaS verification tokens, DNS providers, routing chains |
| Certificate transparency | SAN names, issuers, issuance timing | Related public hostnames, co-issued names, certificate bursts, CT graph structure |
| Identity discovery | Microsoft OIDC, UserRealm, Google identity discovery | Tenant hints, auth style, cloud instance, federation indicators |

The default path is passive. The queried domain's own servers see only the
standard MTA-STS policy fetch. Google CSE and BIMI VMC direct probes require
`--direct-probes`.

## Normalization

By default, recon validates the input, strips browser paste artifacts, and
reduces the target to the registrable apex:

```text
https://www.mail.acme.co.uk/path -> acme.co.uk
mail.acme.co.uk                 -> acme.co.uk
mail.acme.co.uk --exact         -> mail.acme.co.uk
```

This matches where the high-signal records usually live: MX, SPF, DMARC,
tenant-domain bindings, and CT parent scope.

## Subdomains and External Surface

After apex collection, recon enriches a bounded set of public subdomains from
certificate transparency and common high-signal prefixes. This is still passive
DNS work: recon resolves DNS records and CNAME chains, but it does not open web
pages, scan ports, authenticate, or enumerate target services.

Subdomain evidence answers a different question from apex evidence. Apex MX,
TXT, SPF, DMARC, and tenant discovery describe the domain-level posture.
Subdomain CNAME chains describe where visible public hostnames appear to point.
For that reason, recon keeps the per-subdomain result in
`surface_attributions` instead of folding every subdomain provider into the
apex service list.

Output detail depends on the surface:

- The default panel and MCP `lookup_tenant(format="text")` show a compact
  provider-count summary such as `Subdomain surface: Azure App Service (33)`.
- `--full` and `--domains` show the per-subdomain `External surface` section.
- `--json` and MCP JSON-shaped lookup records include the full
  `surface_attributions` array.
- Unmatched CNAME chains are shown as `Unclassified surface` hints in the panel
  and can be emitted for discovery with `--include-unclassified`.

An attribution is an observation about a public CNAME chain, not proof that the
service is active, reachable, or owned by the queried organization.

## Evidence to Slugs

A fingerprint slug is a stable identifier for one observed pattern. Examples:

- `microsoft365`
- `google-workspace`
- `proofpoint`
- `cloudflare`
- `okta`

Slugs come from YAML catalog entries. Each entry names the observable record
shape it matches and, when available, links to vendor documentation. Custom local
entries are additive and live under `~/.recon/`.

## Slugs to Signals

Signals combine slugs and metadata into analyst-readable observations. A signal
might require a minimum number of slugs, a DMARC policy value, a CNAME motif, or
the absence of an expected declared control.

Signals are deterministic and data-driven. They do not call the network and they
do not use a model.

## Graph Structure

Certificate and CNAME data can reveal structure even when individual labels are
randomized or sparse. recon therefore derives:

- CNAME chain motifs.
- CT co-occurrence communities.
- Wildcard SAN sibling sets.
- Deployment bursts.
- Batch-scope ecosystem hyperedges when the operator supplies a batch.

These outputs describe observed public structure. They do not prove ownership or
business relationship.

## Bayesian Posteriors

The optional fusion layer maps observed slugs and signals into a small
hand-specified Bayesian network. It produces posteriors and 80 percent credible
intervals for high-level claims such as:

- Microsoft 365 tenant present.
- Google Workspace tenant present.
- Federated identity indicators present.
- Email-policy enforcement observable.
- CDN fronting observable.

The interval is the important part. Sparse evidence widens the interval and sets
`sparse=true` rather than collapsing to a confident-looking answer.

The network has no learned weights, no runtime training, and no imported
intelligence database. CPT values live in committed YAML and are guarded by
validation and drift tests.

## Provenance

Every high-level claim should trace back to an observable:

```text
DNS TXT or MX or CNAME
-> fingerprint slug
-> signal or posterior binding
-> panel insight or JSON field
```

Use:

```bash
recon contoso.com --explain
recon contoso.com --json --explain
recon contoso.com --explain-dag
```

when a claim needs audit support.

## Caching and Partial Results

recon caches TenantInfo results and CT subdomain lookups locally. Cache failures
degrade to a miss. CT providers are best-effort and can be stale,
rate-limited, or unavailable. A degraded source is named in output rather than
hidden.

For maintainer corpus work, certificate-transparency validation is deliberately
multi-session and aggregate-only. The closed plan is
[c3-ct-validation-plan.md](c3-ct-validation-plan.md); end users do not need it
for normal lookups.

Partial results are valid when at least one source returned clean evidence.
The result reports `partial`, `degraded_sources`, and CT attempt metadata so an
operator can decide whether to retry.

## What Not To Infer

Do not infer:

- Internal workloads.
- Active service versions.
- Exploitability.
- Company ownership from shared tokens or CT co-issuance.
- Use of SaaS products that leave no public DNS or CT footprint.
- Security maturity from a score or a sparse panel.

Those are outside recon's evidence model.

## Where To Go Next

- [limitations.md](limitations.md): passive-observation ceiling.
- [schema.md](schema.md): exact JSON fields.
- [mcp.md](mcp.md): agent-facing local tool surface.
- [assurance-case.md](assurance-case.md): promises mapped to tests.
- [data-handling-policy.md](data-handling-policy.md): public repo disclosure
  rules.
