# Adversarial DNS-record corpus round

**Date:** 2026-08-17

**Decision:** Pattern I (planted administrative tokens) is measured end to end at
the DNS-record layer. The shipped record-role gate holds against every
administrative-only plant the corpus can author for the five gated
tenant/vendor/infrastructure nodes. The correlation.md 4.11 characterization of
Pattern I as "the one pattern the engine does not handle" is corrected: a partial
provenance gate already exists and holds for the record-plantable vector. No engine
change ships in this round; the corpus becomes the standing gate the
provenance-weighting mitigation must pass.

**Disclosure:** Aggregate only. No real target, organization, tenant identifier, or
per-domain value appears; by construction the corpus cannot contain one. Every
fixture is a hand-authored reserved-namespace record set.

## Ladder placement

This is Level 2 evidence (`docs/statistical-assurance.md`): synthetic worlds
sampled from the same model. It uses no real targets, so it licenses no accuracy,
recall, precision, or population rate, and the wording stays "over these
constructed adversarial inputs," never "on real domains." The fixture count M is a
design choice, not a sample size; the result is exact over the corpus and carries
no confidence interval and no extrapolation. What the round measures is narrow and
actionable: on a named, designed-in defect vector, whether the engine moves a
supported decision on evidence a passive adversary can publish for free, and by how
much. A bad number here is directly actionable engine work, not a demotion; the
number turned out to be zero.

## The falsifiable claim, stated before the counts

> Over M constructed Pattern-Ia fixtures, each a clean reserved-namespace DNS
> record set on which the target node is unresolved plus one administrative-only
> planted record, recon (records through replay, merge, and the record-role gate,
> into inference) moved N of M target nodes to a supported decision at the 0.5
> threshold.

## Frozen contract

| Item | Value |
|---|---|
| recon version under test | 2.16.0 |
| Network topology | v1.9.3 (frozen 2026-05-09; 9 nodes) |
| Decision rule | shipped `posterior_dot_fill`, `POSTERIOR_DECISION_THRESHOLD = 0.5` |
| Supported | point estimate on the yes-side of 0.5 (dot fill 2 or 3) |
| Fixture-set SHA-256 (canonical JSON) | `dc7dfef548419e69d0584f917ca766f1ecc657318ef0d8160f02cebf80fe070d` |
| Corpus size | 23 fixtures |
| Network / target contact | none; fully offline record replay |

The corpus is exhaustive over constructed fixtures, so the only frozen objects are
the fixture-set digest, the inference code the run bound to (the shipped v1.9.3
network and 2.16.0 inference path), and the 0.5 threshold. Nothing is sampled, so
nothing else needs freezing. The reproducible detail is the corpus itself
(`validation/adversarial_corpus/`); the aggregate is
[`results.json`](adversarial_corpus/results.json).

## Completed aggregate result

**N = 0, M = 7.** Over the seven gate-path administrative-token fixtures, the
engine moved zero of seven target nodes to supported. The record-role gate holds.

| Pattern | Fixtures | Disposition | Result |
|---|---:|---|---|
| Ia, gate-path administrative tokens | 7 | Expected to hold; a flip is a gate hole | 0 of 7 moved to supported. Gate holds on m365_tenant, google_workspace_tenant, cdn_fronting, aws_hosting, email_gateway_present |
| N, functional-corroborator controls | 2 | Must support (5.6 bullet 2) | Both supported: an Exchange Online MX moved m365_tenant to 0.93, an Akamai edge CNAME moved cdn_fronting to 0.96 |
| C, grouped derivatives and composition | 4 | Non-stacking; gate blocks DAG propagation | All hold: a duplicate token and a duplicate CNAME add nothing; an administrative token does not lift the child node, a functional record does |
| Ib, declarative policy | 1 | Fires by design, not deception | A strict SPF record fires the supporting signal but the node stays unresolved (0.06 to 0.15); the enforcing-DMARC signal that would move it is a collector scalar, not a raw-record plant |
| B, bypass-path scalar probes | 3 | Ungated scalar routes, candidate holes | All moved to supported through an injected non-DNS scalar: `auth_type` moved federated_identity and m365_tenant, `google_idp_name = okta` moved okta_idp |
| G, cross-source conflict dampening | 3 | Claimed dampening should engage | Conflict provenance populated; on an evidenced node the band widened (cdn_fronting 0.148 to 0.161, and the same on m365_tenant). Raw CNAME-target rotation does not reach this mechanism |
| H, administrative-token stuffing | 3 | Record-layer analogue of SAN stuffing | Four unrelated vendor tokens plus an NS delegation move no gated node; grouped m365 tokens do not stack; two record types naming one CDN vendor move nothing |

All 23 fixtures satisfy their pre-registered property.

## Reading the result

**The gate is real and holds (Ia).** Each Ia fixture plants a record that produces
the vendor slug through a non-functional record type: a Microsoft 365
domain-verification TXT, a Google site-verification TXT, a Cloudflare verification
TXT, an Akamai authoritative-DNS delegation, an AWS Route 53 delegation, a
Proofpoint or Mimecast verification TXT. Every one reaches the network as a detected
slug, and none moves its decision node off the prior, because the record-role gate
admits only the functional record type for each claim. This is the first dated
evidence that recon already resists the headline Pattern I vector for tenant and
vendor impersonation. It narrows correlation.md 4.11: the vector is real for a
single-signal detector, but the inference layer already carries a partial
provenance gate that the section did not credit.

**Functional corroborators still support (N, C).** A gate that erased the value of
functionally necessary evidence would be a regression. An Exchange Online MX and an
Akamai edge CNAME each move their node to supported, and beside a functional MX an
added administrative TXT is inert (the grouped derivatives collapse to one
observation). The gate distinguishes an administrative token from a functional
corroborator by record role, exactly the 5.6 bullet 2 property.

**The declarative node cannot be flipped from raw records (Ib).** Planting a strict
SPF record fires `spf_strict`, a supporting signal, but the observed absence of a
DMARC policy group disconfirms and the node stays unresolved. The only signal that
moves `email_security_policy_enforcing` above the threshold is an enforcing DMARC
policy, which is a DMARC-collector scalar, not a value carried on a raw apex record
in this path. So publishing an enforcing DMARC record does move the node, but that
is publishing your declared policy, not impersonating a tenant. Whether an
operator's published policy should count as support for "enforcing" is a product
question, flagged for the roadmap, not scored as a failure here.

**The ungated routes are scalar, not record (B).** `federated_sso_hub` fires on
`auth_type`, and `okta_idp_observed` fires on `google_idp_name == okta` with no
record-role gate at all, the clearest asymmetry with the tenant nodes. Injecting
those scalars moves federated_identity, m365_tenant, and okta_idp to supported. But
these scalars originate in OIDC and UserRealm collection, not in DNS, so a pure-DNS
adversary cannot set them; their record-plant exploitability is nil. They are
reported as candidate gate holes for the provenance-weighting mitigation to close
(extend the record-role discipline the tenant nodes have to the IdP node), scoped
honestly, and never mixed with the gate-path count.

**Dampening engages where it can (G).** A cross-source conflict populates conflict
provenance and, on a node carrying evidence mass above the display-mass floor,
widens the uncertainty band. On an evidence-empty node the band already sits at the
floor, so the conflict penalty is not visible there. A scoping finding: raw
CNAME-target rotation does not itself reach this mechanism, which lives in the
scalar merge (populated by the identity and DMARC collectors), not in
`raw_dns_records`.

## Scope boundaries

The DNS-record adversary's entire reach at this layer is the fingerprint-slug into
record-role-gate into decision-node path. Pattern F (wildcard-certificate rotation)
is a certificate-transparency and related-surface property that the DNS replay path
does not touch (`replay_cached_dns_fingerprints` has no CT channel), so it stays
deferred; the deferral is re-confirmed at this layer, not merely inherited. The
certificate-SAN form of Pattern H likewise needs the certificate collector; the
record-layer analogue exercised here (administrative-token stuffing) tests the same
record-role gate the tenant nodes carry.

## Regression role and next operation

Whatever future mitigation widens the record-role gate, these 23 fixtures are the
standing gate: Ia must stay at N = 0, the functional-corroborator controls (N, C)
must keep supporting, and the bypass probes (B) name the routes a complete gate has
to close. The provenance-weighting mitigation that correlation.md 4.11 and 5.6
describe is separate, larger engine work; this round builds the gate that work must
pass and ships the measurement first. correlation.md 4.11 moves from a stated
commitment to a dated result, and 5.6 gains this corpus as its baseline reference.
