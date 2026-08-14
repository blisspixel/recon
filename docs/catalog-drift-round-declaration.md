# v2.14 Catalog Drift Round Declaration

Status: frozen; collection prohibited until this declaration and its exact
implementation pass protected main

Protocol frozen: 2026-08-14T03:29:15.688759Z

This declaration fixes the final v2.14 catalog round before any re-observation
request. It binds the complete measured portion of the July 17 typed catalog
baseline, the retained prior result, the new collection implementation, and an
aggregate-only comparison rule. The exact frame, prior rows, per-namespace
results, paths, and detailed differences remain in ignored private storage.

## Question

> Which retained bounded-path observation summaries changed when the measured
> 2026-07-17 baseline sample was observed again?

This is temporal re-observation of a convenience sample. It is not an
independent coverage round, a population estimate, a precision or recall
study, or evidence about any particular namespace. A changed summary can be
compatible with public DNS change, resolver variability, source degradation,
or a changed collection regime. The reducer records the change and does not
assign a cause.

## Prior sample and eligibility

The prior result is the complete collection recorded in the
[typed catalog baseline](../validation/2026-07-17-typed-catalog-baseline.md).
It contains 5,202 result rows. The three historical validation-error rows have
no comparable measured observation and were excluded before the frame was
frozen. Every other retained canonical apex appears exactly once, leaving
5,199 rows. The preparer derives that frame directly from the retained result;
no identifier is copied by hand or printed.

The prior sample was collected with certificate transparency disabled,
opt-in direct probes disabled, concurrency four, and the ordinary documented
public-metadata boundary. The new round preserves those settings. It does not
add inputs, substitute newly selected rows, or treat a repeated row as fresh
coverage evidence.

## Observation and interpretation boundary

The July and current catalog digests differ. Comparing classified or
unclassified counts as if the interpretation were fixed would therefore mix
catalog evolution with observed change. The drift reducer compares only these
retained per-path fields:

- `availability`;
- `opportunity_count`;
- `observed_count`; and
- `truncated`.

Classification comparison is permitted only when both the catalog and
interpretation-execution digests match. The catalog digests do not match for
this round, and the legacy prior aggregate predates the execution-digest
commitment, so classified counts, unclassified counts, slugs, confidence, and
inferred services are explicitly not comparable. This follows the shipped
observation-capsule rule: catalog or interpretation-code changes are not silent
observation changes.

For every bounded record type and every frozen row, the evaluator emits one
outcome in this precedence order:

| Outcome | Meaning |
|---|---|
| `unmeasured` | The prior or current result lacks a comparable retained summary. |
| `unavailable` | The current path was explicitly unavailable. |
| `changed` | Both summaries are measurable and at least one frozen comparison field differs. |
| `no_change` | All frozen retained comparison fields are equal. |

`no_change` is intentionally narrow. It does not mean that every DNS value,
unknown owner, certificate, or upstream service was byte-identical.

## Frozen commitments

| Commitment | SHA-256 or count |
|---|---|
| Prior collection revision | `1c130ee7c6c6687491e4423e3987587a4f39b571` |
| Prior retained result | `39655fc31713302803d37a17345f30f3b2a8253da082e3c47509db25e16db7ed` |
| Prior aggregate file | `d9a4f76b0b0999cc82ef492e0e6898515f7ec9f84e2db39b11776d552545ff72` |
| Prior catalog | `f755f5c4626e9d525510c471b84a6f5633e19a81e5792b8a50cb547b0919cc1f` |
| Prior rows / excluded errors / frozen rows | 5,202 / 3 / 5,199 |
| Frozen frame | `d1400df98f3b083dbd0176b1805c95c8204f254c9fa1d2bf2dabe58f61d0b9cd` |
| Generic source | `3205f04193cdd741f2e5914e8f4173a60d9ec171d664c60d08bbe5925a61783e` |
| Generic round plan | `689d6a225c212583bba5c92140bc2df15aa770b65c0d84498570eb8823f20bd6` |
| Generic round manifest | `0bb7c32ea9bb63452f5d800cf93acc5c6d794263c63fe4465709accc92830f53` |
| Drift comparison contract | `0a7b8398cb78bc5244635886591d1e63be1fe5cc79ea2b2779dacc80e73809a1` |
| Current built-in catalog | `206ee855ba9f5107634f0876b66ed46306dbecfaaaff6c8a10a089ac4678baa2` |
| Current execution surface | `01069211619b8be43f4b28e49856cbf5b42269806c549063e7d2485cf7bef309` |
| CT / direct probes / concurrency | off / off / 4 |
| Recurrence threshold | 3 occurrences across 2 namespaces |
| Observed-count review threshold | decline greater than 1 percent for any bounded record type |

The generic manifest binds the current catalog, execution code, package data,
project metadata, dependency lock, frame, collection settings, recurrence
thresholds, and regression budget. The drift sidecar additionally binds the
prior result, aggregate, catalog, collection metadata, eligible frame, and
comparison semantics. `scan.py` rejects a missing sidecar, an implicit prior,
`--no-compare`, a substituted prior run, or any digest mismatch before the
batch process starts.

## Collection and reduction gate

After this declaration and the exact implementation merge through protected
main, the frozen run shape is:

```bash
python validation/scan.py \
    --corpus validation/corpus-private/catalog-drift-20260814/frame-v3.txt \
    --round-kind drift \
    --round-manifest validation/corpus-private/catalog-drift-20260814/round-manifest-v3.json \
    --drift-prior-contract validation/corpus-private/catalog-drift-20260814/prior-contract-v3.json \
    --compare-to validation/runs-private/20260717-202753Z \
    --min-count 3 \
    --concurrency 4
```

The completed run must contain every frozen row exactly once. Reduction then
uses `validation.evaluate_catalog_drift_round` to verify both result digests,
the current pooled aggregate, frame membership, manifest binding, catalog and
execution commitments, and the four outcome classes. Public output may contain
only commitments, aggregate counts and deltas by bounded record type, the
classification-comparability state, and decision flags. It may not contain
apexes, target record values, organization names, tenant identifiers, samples,
paths, per-domain rows, or named changed slugs.

The drift round cannot promote a catalog rule. Any recurrent queue remains a
private review input and still needs an independent provider-controlled basis,
a current recon review date, fictional positive, lookalike-negative and sparse
fixtures, provenance assertions, and a separate fixed-observation regression
decision. The public result must preserve unavailable, unmeasured, changed,
and no-change outcomes even if no rule is proposed.
