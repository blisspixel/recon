# How recon Works

This is the plain-language model overview. For the formal math and prior art,
read [correlation.md](correlation.md). For runtime caps and exact exit codes,
read [operational-contract.md](operational-contract.md).

## The Core Claim

recon answers one narrow family of questions:

What was observed around this domain's public namespace? Which narrow claims
follow from those observations? Which alternatives, conflicts, and unknowns
remain? What evidence would overturn or resolve the result?

The domain is a query coordinate, not an organization identifier. The answer is
a hedged observation with provenance, not a security verdict. The tool can say
"DMARC policy is `p=none`" or "a Microsoft tenant namespace was returned." It
should not say "this organization is secure," "these domains have one owner,"
or "this control is exploitable."

Four questions stay separate: how a value was constructed, whether its source
was successfully observed, whether the narrow claim is supported, conflicted,
disconfirmed within its public model, or unresolved, and when the constituent
observations were made. One lookup is an observation window, not an atomic
snapshot across every provider.

## Inputs

recon collects from three public source families:

| Source | Examples | What it can reveal |
|---|---|---|
| DNS | MX, TXT, SPF, DMARC, DKIM, BIMI, CNAME, NS, SRV, CAA | Email providers, gateways, SaaS verification tokens, DNS providers, routing chains |
| Certificate transparency | SAN names, issuers, issuance timing | Related public hostnames, co-issued names, certificate bursts, CT graph structure |
| Identity discovery | Microsoft OIDC, UserRealm, Google identity discovery | Tenant hints, auth style, cloud instance, federation indicators |

The default path uses bounded public observations. DNS queries go through the
configured recursive resolver, so authoritative DNS infrastructure may observe
resulting resolver traffic. The only default target-owned HTTP or application
request is the standard MTA-STS policy fetch. Google CSE and BIMI VMC direct
probes require `--direct-probes`. The BIMI probe records a plausible certificate
document as an observation; it does not treat unverified certificate-subject
text as corporate identity.

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

A slug is an observed pattern identifier, not a product-use claim. Different
patterns with the same vendor label can have different subjects and semantics:
an administrative token, routing target, and provider-attested tenant response
must not be flattened into interchangeable corroboration.

## Slugs to Signals

Signals combine slugs and metadata into analyst-readable observations. A signal
might require a minimum number of slugs, a DMARC policy value, a CNAME motif, or
the absence of an expected declared control.

Signals are deterministic and data-driven. They do not call the network and they
do not use a model.

The next deterministic architecture step is a machine-enforced claim contract:
for one narrow claim, enumerate the sufficient positive alternatives, genuine
authoritative negatives, required successful observation opportunities,
dependency groups, scope, time semantics, and renderer obligations. Until that
registry exists, prose and regression tests remain the guardrail.

## Graph Structure

Certificate and CNAME data can reveal structure even when individual labels are
randomized or sparse. recon therefore derives:

- CNAME chain motifs.
- CT co-occurrence communities.
- Wildcard SAN sibling sets.
- Deployment bursts.
- Batch-scope ecosystem hyperedges when the operator supplies a batch.

These outputs describe observed public structure. A shared provider-attested
identifier, routing target, administrative token, historical certificate, broad
vendor, and public issuer are different relation types. They do not prove
ownership or business relationship and must not collapse into one relatedness
score.

## Model-Relative Bayesian Diagnostics

The fusion layer maps observed slugs and signals into a small manually encoded
Bayesian network. It runs by default for both single-domain and batch lookups
unless the operator uses `--no-fusion`. The separate batch ecosystem hypergraph
remains opt-in through `--include-ecosystem`. Fusion produces exact posteriors
for the committed model and evidence-responsive uncertainty bands for high-level
claims such as:

- Microsoft 365 tenant present.
- Google Workspace tenant present.
- Federated identity indicators present.
- Email-policy enforcement observable.
- CDN fronting observable.

The point estimate and band are model-relative. For posterior `p` and hand-set
effective display mass `n_eff`, the band uses the Beta shape
`alpha = p * n_eff`, `beta = (1 - p) * n_eff`. When both parameters are at least
one, it uses central 80 percent quantiles if they contain `p`; otherwise it uses
a clamped mean-centered normal fallback. It is not a Bayesian credible interval
over CPT uncertainty and has no general frequentist coverage claim.
`sparse=true` identifies the minimum effective-mass case. The public channel may
still require an unresolved result even when the model emits a number.

The network has no runtime training, bundled estimator, or imported intelligence
database. Parameters live in committed YAML; some are hand-elicited and some
were manually informed by a dated development corpus. Validation and drift tests
establish faithful computation, not that those parameters track reality or
generalize beyond the development cohort.

The panel keeps `Confidence` and `Model support` separate. `Confidence` is the
deterministic source/corroboration tier. `Model support`, when present, describes
where the weakest emitted claim's model-relative mean and uncertainty band sit
against the model threshold. It is not calibrated confidence.

## Provenance

Every high-level claim should trace back to an observable or an explicit
successful-empty observation opportunity:

```text
DNS TXT or MX or CNAME
-> fingerprint slug
-> signal or posterior binding
-> panel insight or JSON field
```

Use `--explain` for the deterministic explanation records and structured
terminal-provenance DAG:

```bash
recon contoso.com --explain
recon contoso.com --json --explain
```

The structured explanation DAG reports `provenance_complete` and
`disconnected_terminals`. A disconnected terminal remains an identified
traceability gap; seeding unrelated evidence does not make its provenance
complete.

Some insight and posture generator associations are reconstructed from rendered
text or proxy rule matches. Completeness is reachability in that emitted graph,
not proof that every reconstructed generator association is exact. The claim
contract roadmap keeps generation-time rule lineage as open work.

Use `recon contoso.com --explain-dag` for the separate Bayesian
evidence-to-network renderer in text, DOT, or Mermaid form. That diagnostic does
not emit the structured `explanation_dag` object or its terminal-completeness
fields.

When collection degraded, `--explain-dag` prefixes text, DOT, and Mermaid
output with `degraded_sources` and the Bayesian `collection-masked units`. This
distinguishes a structurally unobserved dependency unit from a successfully
observed public absence.

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
operator can decide whether to retry. A declarative Bayesian absence is counted
only when its relevant public channel completed. Transient apex TXT, DMARC,
MTA-STS, or MX collection failures mask the affected inference or reporting
channel as unobserved; a successful empty DNS response remains an observed
absence. Exposure and cohort output therefore do not turn an unavailable DMARC,
MTA-STS, or MX channel into a negative control or a missing-configuration gap.

Current delta output compares two rendered snapshots. It suppresses additions
that previous degradation makes unconfirmable, removals that current
degradation makes unconfirmable, and dependent scalar changes unless both
endpoints had the required observation opportunity. It still cannot distinguish
a public-fact change from a catalog, model, collection-option, cache, vantage,
time-evaluation, or software interpretation change. The correlation roadmap
requires replayable observation capsules before making stronger temporal
claims.

## What Not To Infer

Do not infer:

- Internal workloads.
- Active service versions.
- Exploitability.
- Company ownership from shared tokens or CT co-issuance.
- Use of SaaS products that leave no public DNS or CT footprint.
- Organization size from a tenant-domain count or SPF complexity.
- License tier, device enrollment, or fleet composition from public vendor
  indicators.
- Active security-stack or SASE / ZTNA deployment from administrative tokens
  or generic vendor fingerprints.
- A mail-delivery path from provider slugs without functional MX evidence.
- DKIM from the combination of an email gateway and enforcing DMARC.
- A specific external IdP vendor from a generic federated-namespace result.
- Security maturity from a score or a sparse panel.

Those are outside recon's evidence model.

## Where To Go Next

- [limitations.md](limitations.md): public-channel and model limits.
- [schema.md](schema.md): exact JSON fields.
- [mcp.md](mcp.md): agent-facing local tool surface.
- [assurance-case.md](assurance-case.md): promises mapped to tests.
- [data-handling-policy.md](data-handling-policy.md): public repo disclosure
  rules.
