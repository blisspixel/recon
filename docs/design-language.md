# Operator design language

recon's interface should make the evidence boundary easier to understand than
the score. This is a terminal and agent-facing product, not a security-rating
dashboard. The same terms and caveats apply to Rich, plain text, Markdown and
structured output.

## Information hierarchy

Lead with the queried namespace, observed provider or tenant, and confidence.
Keep service categories compact, with related-host attribution separate from
apex services. Put material collection limits next to the result. Offer deeper
evidence through the existing full and explain paths instead of extending the
default panel indefinitely.

Observation, inference and unavailability are different states. A clean
non-match is not a failed source; recovered CT and stale cached CT are not fresh
live collection. Preserve their explicit labels across output formats. Do not
encode a qualification only in color, an icon, or an explanatory footnote.

## Visual semantics

- Use bold for hierarchy and neutral numeric emphasis. The exposure index is
  model-bound, not an overall security grade, so its magnitude does not select
  a red-to-green scale.
- Keep existing status colors attached to named collection or evidence states.
  Confidence uses both a written level and the existing marker count; color
  alone does not communicate the level.
- Preserve one main divider, stable label alignment, and hanging continuation
  indentation. Text wraps at the actual console width; decorative rules do not
  wrap into extra rows. Ordinary wide output retains its established layout.
- Preserve useful content and styles at 40, 60 and 80 columns. Exercise long
  identifiers and wide Unicode characters. Do not hide missing text by changing
  a golden rendering to match a defect.
- Honor automatic terminal detection and the existing color overrides. Piped
  structured data must remain separate from diagnostics on stderr.

## Quantitative display

Show units and denominators explicitly. A proportion based on eligible rows
must not appear to describe every resolved row. Cohort tables identify the
80 percent Wilson/binomial interval and explain that it is not a population
guarantee. Render unavailable quantities as `n/a`, not zero. Keep rounded
presentation separate from unrounded threshold decisions.

## Brand direction

The proposed mark is a simple open frame with distinct evidence paths: a bounded
namespace, incomplete observation and traceable relationships. It must not
resemble a rune, targeting reticle, security certification or ownership seal.
The mark is decorative identity, not a finding or confidence indicator.

Logo concepts are not approved product assets. Before adopting one, verify a
single-color version at small size, light and dark backgrounds, clear space,
and accessible text alternatives. Keep the lowercase wordmark and the CLI
command legible without requiring the symbol to explain the product.

## Regression checks

`tests/test_panel_responsive_layout.py` preserves wide output and verifies
narrow-width content and style retention. `tests/test_exposure_visual_semantics.py`
pins neutral index styling. `tests/test_cohort_display_semantics.py` checks
units, denominators and unavailable values. `tests/test_mcp_collection_notes.py`
keeps material CT caveats aligned across interfaces. The generated terminal
demo and existing golden renders remain independent integration gates.
