# Evidence and catalog improvement loop

Date: 2026-09-13 UTC

## Objective

Improve observations from existing public channels using reproducible failures,
current vendor support, and automated acceptance. No target collection,
interviews, private inventory, or paid model service was used.

## Evidence-strength correction

Previously, one MX evidence occurrence scored 0.8889, while 100 identical
copies scored 0.9952. A second matching rule name also added strength to the
same retained value. Regression tests reproduced the inflation before the fix.

The diagnostic now counts exact `(slug, source_type, raw_value)` tuples once.
Rule labels do not add observations, input order does not change the result,
and opaque values retain their case. Both one and 100 copies score 0.8889;
two distinct MX values retain the existing 0.9091 result. All provenance
occurrences remain in the record. CLI and MCP use the same corrected values,
and failed channels still cannot corroborate retained observations.

This is a bounded idempotence correction. Distinct values or source types can
share an underlying cause; they are not thereby independent. No priors, CPTs,
weights, public field names, or calibration claims change.

## Shopify rule disposition

Shopify's current [third-party domain verification guide](https://help.shopify.com/en/manual/domains/add-a-domain/connecting-domains/verify-domain-ownership)
specifies a TXT value at `shopify_verification` for the root-domain transfer
workflow. Add `subdomain_txt`, `shopify_verification:.`, dated to this review.
Publication of the value supports an administrative verification indicator.
It does not establish successful verification, transfer, account ownership,
SSO, a live store, or plan. The documented subdomain-specific suffix form stays
outside this fixed-owner rule and creates no variable-owner probing.

The existing apex prefix is a separate undated rule. The cited page does not
verify its grammar, so its date remains unset and its unsupported account/SSO
prose is removed. Shopify routing descriptions likewise describe retained DNS
routes without asserting current storefront or asset activity. The broad
routing patterns retain their undated status.

## Repeatable acceptance

The MCP follow-up checked the [current protocol version](https://modelcontextprotocol.io/docs/2026-07-28/learn/versioning)
and [SDK 2.2.0 release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.2.0).
All 24 isolated checks pass on SDK/types 2.2.0. The older 1.28.1 and 2.0.0
rows also pass. The matrix retains unrelated locked dependencies while allowing
the SDK's required companion types to follow its version. Local defaults and
CI now include the current stable SDK, with a parity regression for that list.

[Agent Plugins v1.0.0](https://agent-plugins.org/specification) remains Published.
The official manifest and MCP schema downloads match the vendored bytes:
manifest SHA-256 `0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883`,
MCP SHA-256 `6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb`.
The generated package passes offline schema and layout validation. A built-wheel
probe outside the checkout also passes both manifest launches, including
relocation with a separate client data directory, 23 tools, six resources,
retained client configuration, and zero attempted external socket operations.
This exercises the packaged server with emulated plugin expansion; desktop
client installation and skill execution remain separately unmeasured.

Run the focused regression command:

```text
uv run pytest tests/test_bayesian_fusion.py tests/test_mcp_parity.py tests/test_catalog_claim_boundaries.py
```

The tests cover repetition, rule aliases, permutation, distinct values and
slugs, opaque case, source failure, CLI/MCP values, exact owner provenance,
wrong owners, empty observations, and wildcard TXT. Property tests generate
additional evidence combinations. Rebuild the catalog with
`uv run python scripts/generate_fingerprint_catalog.py --write`, then run
`uv run python scripts/check.py` for the full coverage and contract gate.

The full run also exposed a diagnostic rendering defect: terminal wrapping
inserted newlines into long interpreter paths. Doctor headers now preserve
copyable interpreter and package paths, with a narrow-console regression that
includes literal markup characters. The section-link checker now prunes
virtual environments and the established root agent scratch directories before
descent. Nested misplaced scratch stays visible. Its regressions also ensure
sentence punctuation cannot hide a dangling reference or split an identifier.

The existing `AGENTS.md` remains the shared instruction source. Its refinement
links bounded work, current primary research, canonical implementation seams,
mechanical verification, and distinct compatibility claims. Runbook regressions
now require automated review evidence for authorized local work while retaining
explicit instructions for commit, push, release, and publication.

## Verification result

The complete canonical gate passed on an isolated Linux checkout with the
same Git tree as the Windows working patch: uv 0.11.17, Python 3.13.13,
7,455 tests passed, 16 skipped, and 91.53 percent branch-aware coverage against
the unchanged 90.2 percent floor. Lint, formatting, strict Pyright, catalog,
schema, documentation, and contract stages all passed. Windows focused tests
and the rebuilt installed-wheel probe also passed; the latter used Python
3.14.7 and MCP/types 2.2.0. This records local verification, before hosted CI
and release publication.

These fixtures establish tested implementation behavior and documented-pattern
coverage. They do not measure real-world precision or prove service use. The
next pass should reuse these negative cases on other vendor families and
characterize shared derivations before extending dependency math.
