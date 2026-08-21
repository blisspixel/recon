# Tencent EdgeOne fingerprint review

Date: 2026-08-21 UTC

Scope: the five existing `tencent-edgeone` CNAME-target rules and the missing
documented shard 0 form

Collection boundary: current public Tencent Cloud documentation and
provider-controlled public SDK or CLI examples only; no target-domain lookup,
corpus row, credential, or direct probe

## Question

Do the six `eo.dnse0.com` through `eo.dnse5.com` CNAME-target forms have
current first-party support for an EdgeOne routing observation, and are the
catalog claims no stronger than that evidence?

## Evidence and disposition

| Pattern | Current first-party evidence | Disposition | Claim boundary |
|---|---|---|---|
| `eo.dnse0.com` | The current [CheckCnameStatus API example](https://www.tencentcloud.com/document/product/1145/56175) returns this suffix as the EdgeOne-assigned CNAME for an access domain. | Add the missing rule and date it. | EdgeOne routing relationship only; no traffic, feature, or state claim. |
| `eo.dnse1.com` | No current first-party page reviewed in this pass names this exact `eo` shard. | Retain the existing observation undated and remove the generic product-root reference. | Legacy catalog observation only. |
| `eo.dnse2.com` | The current [ModifyDnsRecords API example](https://www.tencentcloud.com/document/product/1145/67541) uses this suffix as CNAME content. | Date and narrow the rule. | EdgeOne routing relationship only. |
| `eo.dnse3.com` | The current [DescribeAccelerationDomains API example](https://www.tencentcloud.com/document/product/1145/54132) returns this suffix in the `Cname` field. | Date and narrow the rule. | EdgeOne routing relationship only. |
| `eo.dnse4.com` | No current first-party page reviewed in this pass names this exact `eo` shard. | Retain the existing observation undated and remove the generic product-root reference. | Legacy catalog observation only. |
| `eo.dnse5.com` | The current [DescribeL4Proxy API example](https://www.tencentcloud.com/document/product/1145/59024) returns this suffix for an EdgeOne layer-4 proxy. | Date and narrow the rule. | EdgeOne routing relationship only. |

Tencent's general CNAME setup page confirms that EdgeOne assigns CNAME values,
but it does not name an exact suffix. The shared-CNAME API separately documents
`share.dnse[0-5].com`; that is not treated as evidence for every
`eo.dnse[0-5].com` shard. Exact shard dates therefore come only from the four
current examples above.

## Changes

- Add the missing, currently documented `eo.dnse0.com` CNAME-target rule.
- Date shards 0, 2, 3, and 5 against exact current first-party pages.
- Keep shards 1 and 4 undated instead of extending evidence by inference.
- Replace product and workload assertions with the narrower observation that a
  CNAME chain has an EdgeOne routing relationship.
- State explicitly that a match does not establish active traffic, enabled CDN
  or WAF features, or current configuration state.

## Regression evidence

`tests/test_tencent_edgeone_fingerprints.py` pins:

- the exact reference and review date for all four supported shards;
- the empty reference and undated disposition for shards 1 and 4;
- positive suffix matches for all six shards;
- deceptive suffix rejection for every shard; and
- infrastructure-tier classification under the stable `tencent-edgeone` slug.

The generated catalog contains 869 entries, 692 unique slugs, and 1,109
detections. Of those detections, 149 are dated (13.4 percent), and none of the
dated rules is stale at the 365-day threshold.
