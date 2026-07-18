# Synthetic panel render review

This tracked artifact records aggregate panel-shape evidence only. Detailed
panel text and fixture-by-fixture rows are intentionally written to the
gitignored `validation/agentic_ux/local/` directory.

## Current aggregate

Local rendering on 2026-07-18 discovered 81 fixture paths:

- 79 generated synthetic corpus fixtures rendered successfully
- 1 synthetic dense agentic fixture rendered successfully
- 1 deliberately incomplete synthetic sparse fixture produced the expected
  loader-contract error because its display name is null
- Multi-cloud rollup rendered on 5 of the 79 generated corpus fixtures
- Passive-DNS ceiling rendered on 70 of the 79 generated corpus fixtures
- The dense agentic compatibility fixture rendered neither surface, as pinned
  by `tests/test_agentic_ux_compatibility.py`

The generated-corpus counts exactly match
`validation/synthetic_corpus/aggregate.json`. All identities use reserved
`.invalid` names. No detailed panel output, target row, real or non-synthetic
tenant identifier, or raw target evidence value is tracked.

## Local reproduction

Run `python validation/synthetic_corpus/render_snapshots.py`. The default output
is `validation/agentic_ux/local/render-snapshots.md`, which is gitignored.
