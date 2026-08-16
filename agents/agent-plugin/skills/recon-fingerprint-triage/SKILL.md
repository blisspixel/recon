---
name: recon-fingerprint-triage
description: Triage recon fingerprint candidates across the bounded DNS catalog surface. Reads private single-domain discovery output, aggregate catalog baselines, or candidate queues, then classifies candidates as pending, promoted, rejected, or deferred under the v2.14 catalog-quality gates. Use when the user asks to find missing fingerprints, review unclassified DNS observations, or improve catalog coverage.
license: Apache-2.0
compatibility: Requires recon-tool 2.15.0 or a compatible v2 release and Python 3.11+. Live lookups require public network access; MCP launch requires recon on PATH.
metadata:
  author: blisspixel
  version: 2.15.0
---

# recon-fingerprint-triage

This skill reviews the bounded public DNS observations that recon already
collects and helps maintainers improve the fingerprint catalog. It supports the
multi-record v2.14 quality loop rather than treating catalog growth as a count
of new CNAME suffixes.

This is the portable Agent Skills form used by the schema-pinned v2.15
candidate. It omits client-only frontmatter and does not depend on experimental
`allowed-tools` behavior. Package compatibility remains unclaimed until the
frozen representative-client evaluation is complete.

## When to use this

Use this skill when the user wants to:

- review unmatched DNS observations by record type;
- triage a private catalog baseline or recurrence queue;
- assess a proposed fingerprint rule;
- strengthen an existing slug with an independent evidence path;
- prepare a catalog patch and its required fixtures.

For an ordinary domain lookup, use the base `recon` skill. This skill is for
catalog maintenance, not general domain intelligence.

## Inputs

Choose the narrowest input the user supplied. Treat every real-domain input and
every per-domain row as private working data.

### A. Single-domain discovery

Run the ordinary validated-domain workflow described by the base `recon` skill:

```text
recon <validated-domain> --json --include-unclassified
```

Read all three catalog-discovery collections when present:

- `dns_catalog_summaries` for bounded opportunity and classification counts;
- `unclassified_dns_observations` for typed unmatched values;
- `unclassified_cname_chains` for the historical related-host CNAME view.

The payload is a private review aid. Do not copy its queried domain, owner
names, opaque tokens, target-owned record values, tenant identifiers, or
per-domain rows into a committed memo, fixture, issue, pull request, or other
public artifact.

### B. Multi-record catalog round

Use the private outputs produced by `validation/catalog_baseline.py` and the
round protocol in `docs/catalog-strategy.md`. Keep these dimensions separate:

- `cname_target` related-host chains;
- apex `cname`;
- non-SPF `txt`;
- `spf` include and redirect targets;
- `mx` and `ns` hosts;
- `caa` issuer values;
- `dmarc_rua` destinations;
- bounded owner-qualified `subdomain_txt`;
- bounded `srv` observations.

Do not pool unlike record types into one coverage rate. Preserve the round's
catalog digest, collection options, source-opportunity counts, unresolved and
unavailable counts, truncation state, stratum, and frozen regression budget.

### C. Historical CNAME candidate queue

`gaps.json` or `candidates.json` from `validation/find_gaps.py` and
`validation/triage_candidates.py` remains accepted for the historical
`cname_target` path. Its recurrence counts are a prioritization signal, not
proof that a pattern is correct or promotable.

## Dispositions

Every new candidate begins as `pending`. Assign one of these dispositions and
record the reason:

1. `pending`: plausible, but one or more promotion gates remain open.
2. `promoted`: all promotion gates passed and the patch plus tests are ready.
3. `rejected`: the candidate is over-broad, target-specific, unsupported,
   misleading, or fails an independent negative or regression budget.
4. `deferred`: the candidate may be useful later, but the record is too rare,
   the owner space is not enumerable, or no current independent basis exists.

Never describe a candidate as promoted merely because a YAML stanza was
drafted or a pattern matched the development data.

## Mandatory promotion gates

A candidate remains `pending` until every item below is satisfied:

1. **Exact rule shape.** Name the exact supported record type and the narrowest
   reusable pattern. State whether matching is exact, prefix, suffix, or the
   type-specific grammar documented in `docs/fingerprints.md`.
2. **Independent basis.** Cite a current provider-owned public reference or a
   disclosure-safe aggregate basis that did not consume the same row as both
   predictor and label. Repetition alone is not an independent label.
3. **recon rule review date.** Set `verified: YYYY-MM-DD` to the date the
   fingerprint pattern was last checked against that basis. This scalar is
   recon catalog metadata. It is not an Open Knowledge Format `verified` event
   and does not assert that a target uses the product.
4. **Positive fixture.** Add a reserved synthetic positive that proves the
   intended rule fires and preserves its hedged claim boundary.
5. **Lookalike-negative fixture.** Add a near miss that proves the rule does not
   broaden into an adjacent vendor, shared parent zone, customer hostname, or
   unrelated value.
6. **Sparse-result fixture.** Prove the rule does not turn a thin or degraded
   observation into a stronger product-use, ownership, or maturity claim.
7. **Provenance assertions.** Prove the emitted service or insight retains the
   exact rule, evidence type, observed value scope, and source opportunity
   required by the claim audit.
8. **Frozen regression budget.** Run the candidate against the predeclared
   round budget. Report the aggregate before-and-after result. Reject or leave
   pending any rule that exceeds it. Do not tune the pattern or budget on an
   independent holdout after reading its result.

If the public reference documents only a setup flow and not the proposed token
or hostname, say so. A vendor name or generic documentation homepage does not
silently become exact support for an opaque pattern.

## Record-specific review

- For `cname_target` and `cname`, prefer the stable provider-controlled product
  zone. Reject customer-specific hosts and broad shared-cloud roots.
- For `txt` and `subdomain_txt`, retain only a documented reusable prefix or
  exact non-secret marker. Never publish an opaque verification token.
- For `spf`, distinguish includes and redirects and preserve the observed
  delegation semantics.
- For `mx` and `ns`, describe routing or delegation. Do not upgrade it to
  product activity or organizational ownership.
- For `caa`, describe issuer authorization. Do not claim certificate issuance
  or deployment.
- For `dmarc_rua`, describe the published aggregate-report destination. Shared
  reporting, delegated administration, and stale configuration remain
  compatible explanations.
- For `srv`, preserve owner, service, and target semantics. A port or priority
  value does not establish reachability.

Same-zone and brand-similar targets are noise-filter candidates, not ownership
facts. An unfamiliar hostname stays pending or deferred until an independent
provider basis identifies a reusable pattern.

## YAML proposal shape

Use the existing canonical name when extending a slug. Follow the exact
type-specific grammar in `docs/fingerprints.md`. A typical proposal is:

```yaml
- name: <canonical display name>
  slug: <lowercase-kebab>
  category: <catalog category>
  confidence: <low | medium | high>
  detections:
  - type: <exact supported record type>
    pattern: <minimal reusable pattern>
    reference: <current provider-owned URL when available>
    verified: <YYYY-MM-DD>
    description: <narrow observable meaning and compatible alternatives>
```

`tier` is valid only where the current fingerprint grammar permits it. If the
basis is a disclosure-safe aggregate rather than a provider URL, name the dated
aggregate memo in the review evidence instead of inventing a reference URL.

Before proposing a new slug, inspect the existing catalog and
`src/recon_tool/formatter/classify_tables.py:CATEGORY_BY_SLUG`. Reuse the exact
canonical name for an existing slug. Add a formatter category mapping only when
the existing classification path requires one.

## Output format

Return these sections:

1. **Disposition summary.** One row per candidate with record type,
   pending/promoted/rejected/deferred state, and a short reason.
2. **Gate ledger.** Show pass, fail, or missing for exact shape, independent
   basis, recon `verified` date, three fixture classes, provenance, and frozen
   regression budget.
3. **Proposed patch.** Include YAML and category changes only for candidates
   whose evidence is sufficient to review. Label the patch `pending` until all
   gates and tests pass.
4. **Fixture and test plan.** Name the reserved synthetic positive,
   lookalike-negative, sparse-result, provenance, and regression checks.
5. **Private follow-up.** List missing evidence without reproducing real target
   values.

For a public or committed artifact, include only generic provider patterns,
provider-owned references, reserved synthetic fixtures, and disclosure-safe
aggregate counts. Never include evaluated apexes, organization names, tenant
identifiers, opaque tokens, target-owned owner names or record values,
per-domain rows, or unsuppressed small strata.

## Verification

Use reserved synthetic fixtures for review. Run the relevant focused catalog
tests, then the freshness and generated-artifact gates. Typical focused tests
include:

```text
pytest tests/test_fingerprints.py tests/test_catalog_discovery.py \
  tests/test_dns_catalog_boundaries.py tests/test_fingerprint_freshness_gate.py
```

Also run the project-prescribed lint, full test, coverage, generated-artifact,
and CI-equivalent gates before calling the change complete. A live lookup of a
real target may be useful in the maintainer's private workspace, but it is not a
public regression fixture or permission to publish the value.

## Hard boundaries

- Do not perform direct probing beyond recon's documented collection boundary.
- Do not promote a pattern from a vendor name, hostname intuition, or recurrence
  count alone.
- Do not use a development row as its own independent precision label.
- Do not infer active use, ownership, control, plan tier, traffic, or security
  maturity from a fingerprint.
- Do not expose real-target data in public review artifacts.
- Do not map recon rule `verified`, fingerprint `confidence`, or private
  occurrence counts to OKF `verified`, trust tiers, or `usage_count`.
- Do not turn offline schema validation into an unqualified Agent Plugins
  compatibility or future-draft conformance claim.
