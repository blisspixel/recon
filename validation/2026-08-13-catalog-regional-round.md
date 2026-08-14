# Catalog Regional-Round Result

**Date:** 2026-08-13

**Decision:** Regional round complete; accept six documented provider-family
additions and move to the vendor-seed round

**Disclosure:** Aggregate only. No selected namespace, record value,
organization name, tenant identifier, or per-domain row is included.

## Question and boundary

The frozen question was which recurrent bounded record-type catalog gaps appear
across equal discovery quotas from large eligible ccTLD namespaces in each
canonical UN M49 region. Five strata each received an equal 200-namespace
discovery quota. Those quotas are not population weights. The result is a
comparison of ccTLD namespace strata, not registrant location, organizational
presence, service geography, or regional Internet prevalence.

Preparation, official-source, selection, and collection commitments are in the
[regional-round declaration](../docs/catalog-regional-round-declaration.md).
The baseline run completed all 1,000 rows with zero error rows and 45 partial
rows. Certificate transparency and opt-in direct probes were disabled by
contract.

| Commitment | Value |
|---|---|
| Frozen frame rows | 1,000 |
| Frozen frame SHA-256 | `02544fe04b9c21fa74f1334d1884db2044dd3de2ac30686db661eb5590a5d7e3` |
| Baseline result SHA-256 | `24ae79dfbbc2d0023148a44649be9c3aae5ad9caf25b8067a7b018a7721ab574` |
| Baseline pooled aggregate SHA-256 | `b980dfa8320d024b057299ee568c9197fff93693b657eccac4aa4dff97c3b872` |
| Baseline catalog SHA-256 | `78e9641abb60fd310a834b141d2d2c553afe7026893526f4af733221124534c8` |
| Private round-manifest commitment | `7209b80ef5b248802a6b0fe0ecb8f9d53889a26aaae7b46272d7e28fcfbcad4b` |
| Stratified aggregate file SHA-256 | `d10d8b5c8ee1d5f77574a7562ab9397b5f6dcfc40c32c132622ea5e410a0968b` |
| Stratified reducer SHA-256 | `7fbf7aef2b1310b5bcdc238d4dc41597a84a5f2bead53311367bc39ff1f9f835` |

## Descriptive stratum result

Classification rates use observed values as their denominators. `Stratum 0`
through `Stratum 4` preserve the frozen order: Africa, Americas, Asia, Europe,
and Oceania. Globally marketed ccTLDs remain in their exact IANA delegation and
UN M49 grouping.

| Record type | Stratum 0 | Stratum 1 | Stratum 2 | Stratum 3 | Stratum 4 |
|---|---:|---:|---:|---:|---:|
| `cname_target` | 0.771429 | 0.645161 | 0.582090 | 0.400000 | 0.703390 |
| `cname` | 0.281250 | 0.282353 | 0.225000 | 0.203390 | 0.447368 |
| `txt` | 0.660274 | 0.801386 | 0.625806 | 0.716632 | 0.470785 |
| `spf` | 0.664975 | 0.615063 | 0.420118 | 0.389961 | 0.648402 |
| `mx` | 0.694215 | 0.705167 | 0.596552 | 0.386100 | 0.708185 |
| `ns` | 0.566355 | 0.683301 | 0.408915 | 0.377939 | 0.669776 |
| `caa` | 0.933884 | 0.893939 | 0.896552 | 0.761905 | 0.943662 |
| `dmarc_rua` | 0.378049 | 0.448718 | 0.278689 | 0.328947 | 0.521739 |
| `subdomain_txt` | 0.250000 | 0.052632 | 0.076923 | 0.000000 | 0.000000 |
| `srv` | 0.352113 | 0.724138 | 0.571429 | 0.594595 | 0.800000 |

The strata expose different gap shapes within this frame. MX, NS, and SPF
classification are materially lower in the Europe stratum than in the
Americas or Oceania strata, while CAA is highly classified in every stratum.
The recurrent candidate-bucket counts were 21, 19, 31, 42, and 6 in frozen
stratum order. These differences prioritize research. They do not establish
population rates or causal regional explanations.

## Candidate dispositions

Six provider families cleared the complete evidence gate. Their record
meanings come from provider-controlled documentation, not recurrence alone:

| Disposition | Family and additions | Aggregate basis | Claim boundary and primary reference |
|---|---|---:|---|
| Accepted | Cloudflare Email Service, SPF `_spf.mx.cloudflare.net` | 11 previously unclassified SPF values | Authorizes Cloudflare mail sending or forwarding; no inbound-routing, CDN, or security-product claim. [Cloudflare Email Service domain configuration](https://developers.cloudflare.com/email-service/configuration/domains/) |
| Accepted | Hostinger DNS, NS suffix `dns-parking.com` | 38 previously unclassified NS values | Hostinger manages authoritative public DNS; no website-hosting, email-hosting, or ownership claim. [Hostinger nameserver lookup](https://support.hostinger.com/en/articles/8671230-how-to-look-up-domain-nameservers) |
| Accepted | Hostinger Email, MX `mx1.hostinger.com` and `mx2.hostinger.com`, SPF `_spf.mail.hostinger.com` | 24 MX and 17 SPF values | MX observes inbound routing and SPF authorizes sending; neither establishes mailbox activity or web-hosting use. [Hostinger MX records](https://support.hostinger.com/en/articles/4407237-hostinger-email-mx-records), [Hostinger SPF record](https://support.hostinger.com/en/articles/1583673-what-is-the-spf-record-for-hostinger-email) |
| Accepted | Locaweb Email, four exact MX routes, SPF `_spf.locaweb.com.br`, CNAME target `webmail-seguro.com.br` | 20 MX, 6 SPF, and 3 CNAME-target values | MX observes inbound routing, SPF authorizes sending, and the application-tier CNAME observes a hosted webmail surface. None establishes mailbox activity, ownership, or broader product use. [Locaweb MX and SPF configuration](https://www.locaweb.com.br/ajuda/wiki/como-configurar-o-mx-e-mail-locaweb/), [Locaweb webmail access](https://www.locaweb.com.br/ajuda/wiki/como-acessar-o-webmail-email-locaweb/) |
| Accepted | OVHcloud Email, MX suffix `mail.ovh.net` and SPF `mx.ovh.com` | 13 MX and 8 SPF values | MX observes OVHcloud inbound routing across multiple mail products and SPF authorizes sending; no specific plan or mailbox-activity claim. [OVHcloud MX configuration](https://docs.ovhcloud.com/en/guides/web-cloud/domains/dns-zone-mx), [OVHcloud SPF configuration](https://docs.ovhcloud.com/en/guides/web-cloud/domains/icloud) |
| Accepted | Titan Mail, MX `mx1.titan.email` and `mx2.titan.email`, SPF `spf.titan.email` | 6 MX and 6 SPF values | MX observes inbound routing and SPF authorizes sending; neither establishes mailbox activity. [Titan domain setup](https://support.titan.email/hc/en-us/articles/360036853934-Setup-Titan-for-your-domain) |

Every added detection carries `verified: 2026-08-13`. Reserved fictional tests
cover exact positive matches, deceptive DNS-suffix lookalikes, sparse results,
evidence occurrences, source-opportunity accounting, and catalog-match
provenance. The existing Hostinger Email CNAME rule also receives a current
provider reference, review date, scoped description, and product metadata.

The pooled recurrence queue contained 136 buckets before research. Candidates
without current exact product documentation remain deferred, including exact
OVH mail-configuration and broad Locaweb autodiscovery targets. Generic or
shared endpoints, opaque TXT prefixes, organization-specific DMARC report
destinations, undocumented regional SPF internals, and vendor guesses were not
promoted. Repetition is not a label, and a DMARC report destination is not a
trust score or adoption claim.

Unavailable outcomes are retained as the 45 partial baseline rows, distributed
11, 5, 10, 8, and 11 across the five strata. CT-dependent CNAME breadth and
opt-in direct-probe evidence were unmeasured by design.

## Promotion budget and fixed-observation decision

The frozen budget required at least 0.001 classified-rate uplift in every
affected record type and zero regression in every protected type. The
fixed-observation evaluator applied only the proposed candidate catalog to the
exact retained baseline observations. It performed zero network requests and
kept every denominator unchanged.

| Record type | Baseline classified / observed | Added | Counterfactual rate | Delta |
|---|---:|---:|---:|---:|
| `cname_target` | 319 / 504 | 3 | 0.638889 | +0.005952 |
| `mx` | 956 / 1,522 | 63 | 0.669514 | +0.041393 |
| `ns` | 1,438 / 2,661 | 38 | 0.554679 | +0.014281 |
| `spf` | 592 / 1,083 | 48 | 0.590951 | +0.044321 |

All six unaffected record types had exactly 0.000000 change. All four affected
types exceeded the 0.001 minimum, all six candidate families were observed,
and no type exceeded the zero-regression budget. The causal promotion decision
is accepted.

| Counterfactual commitment | Value |
|---|---|
| Candidate catalog SHA-256 | `206ee855ba9f5107634f0876b66ed46306dbecfaaaff6c8a10a089ac4678baa2` |
| Evaluator SHA-256 | `99fb50eacc760d71cc6a85d7b71f3f94e1c1f78059fa590503678502a1cacf00` |
| Clean protected-main revision | `d19b888e3f6826df33994be3b46d91751438a7bd` |
| Counterfactual file SHA-256 | `6c1888fad80508e595da398a1c3139d389146a34dec06356445025673f3abd26` |
| Network requests | 0 |
| Identifiers printed | 0 |

The evaluator was rerun from the clean protected-main revision after merge. It
reproduced the same per-family and per-type additions and binds the causal
decision directly to the catalog digest used by the live replay.

## Protected-main live replay

The same frozen 1,000-row frame was replayed from clean protected main with CT
and direct probes still disabled. It completed all 1,000 rows with zero errors,
39 partial rows, and no timeout. Partials were distributed 8, 4, 9, 9, and 9
across the five frozen strata. Every stratum reducer membership check passed.

| Replay commitment | Value |
|---|---|
| Protected-main revision | `d19b888e3f6826df33994be3b46d91751438a7bd` |
| Replay manifest SHA-256 | `c7e0d97c79adc2f8fe56cd6902aa642d4ada54fa0e853551cf1025bbd36b4125` |
| Replay catalog SHA-256 | `206ee855ba9f5107634f0876b66ed46306dbecfaaaff6c8a10a089ac4678baa2` |
| Replay execution SHA-256 | `d9b199d0d731b1684af8ec7eb436ba4e73176e1b3cdb350a003f7cc138e152b6` |
| Replay result SHA-256 | `60e721dfe716894e2f3c878e00dd8cd7663c5d8bfddaa7e55366500b5ee110d8` |
| Replay pooled aggregate file SHA-256 | `1df34604024031251ef562792d6e5262d8d168cf1041429b506648e0391f79ed` |
| Replay stratified aggregate file SHA-256 | `083de84830b4ac99c75483de6f80ee2a4a161667fefb5723ed9c34108500f5ad` |
| Records / errors / partials | 1,000 / 0 / 39 |

The live pass is an operational replay, not the causal comparison, because
public DNS changed between passes. Its affected-type classified counts moved
by exactly the fixed-observation additions, while observed denominators also
changed slightly:

| Record type | Baseline classified / observed | Replay classified / observed | Replay rate |
|---|---:|---:|---:|
| `cname_target` | 319 / 504 | 322 / 504 | 0.638889 |
| `mx` | 956 / 1,522 | 1,019 / 1,525 | 0.668197 |
| `ns` | 1,438 / 2,661 | 1,476 / 2,666 | 0.553638 |
| `spf` | 592 / 1,083 | 640 / 1,085 | 0.589862 |

CAA, DMARC RUA, and owner-qualified TXT retained identical classified and
observed counts. CNAME, TXT, and SRV had small denominator or classified-count
changes consistent with live public-DNS drift. Those changes do not alter the
fixed-observation decision.

## Decision and next operation

The regional round is closed. It supports these bounded additions and
explicitly does not support broad catalog growth, a population coverage claim,
or a registrant-geography claim. The vendor-seed relationship label,
denominator, exclusions, disclosure protocol, and fail-closed tooling are now
implemented, along with bounded source acquisition and immutable receipt
binding. The 33-row HubSpot contract produced the closed aggregate-only
[vendor-seed result](2026-08-14-catalog-vendor-seed-round.md), with 29
corroborated and 4 observed-silent rows and no catalog promotion. The measure
is relationship corroboration, not recall, because a provider relationship
does not label publication of a particular DNS record. Frozen-sample drift is
next. Agent Plugins packaging remains v2.15
work, and OKF v0.2 remains a future named-consumer, caller-owned projection
rather than a replacement for recon's versioned JSON or catalog evidence model.
