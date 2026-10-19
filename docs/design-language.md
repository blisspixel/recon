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

## Voice and qualifiers

- Use a colon between a label and its value (`Tenant: n/a`, `Reserved name:
  results are public residue, not an organization.`) and a spaced hyphen for
  an aside (`sub.example.com - Synthetic Alpha (unverified)`). Output strings
  carry no em dash or en dash; `tests/test_caveat_parity.py` scans the string
  literals of `formatter/`, `cli/` and `server/` to keep it that way.
- Render an unavailable value as `n/a`, never a dash placeholder.
- A qualifier is a word, present on every surface: the panel, `--plain`,
  `--md`, MCP text, and a field in `--json`. A provider-reported display name
  reads `(unverified)`, muted on the panel; the word, not the color, carries
  it. A reserved special-use queried name gets one line under the title,
  `Reserved name: results are public residue, not an organization.`, and
  `"reserved_name": true` in JSON. The wording lives once, in
  `src/recon_tool/formatter/caveats.py`.

## Visual semantics

- Use bold for hierarchy and neutral numeric emphasis. The exposure index is
  model-bound, not an overall security grade, so its magnitude does not select
  a red-to-green scale.
- Every color comes from one role table, `src/recon_tool/formatter/theme.py`,
  mapped to the terminal's 16 named colors so a theme switch recolors recon.
  No hex or 256-color values, no ANSI 0 (several theme generators, Omarchy's
  included, set it to the background), and no magenta.

  | Role | ANSI | Used for |
  | --- | --- | --- |
  | accent | cyan | headings in the welcome screen, discovered domains, commands in hints |
  | success | green + word | `ok`, `match`, High confidence marker |
  | warning | yellow + word | `warn`, partial, cache recovered, unverified, Low confidence marker |
  | error | red + word | `fail`, source unavailable |
  | info | blue + word | Medium confidence marker, vantage, mode |
  | muted | dim default foreground | labels, provenance, clean no-match |

  Gap severity uses high red, medium yellow and low blue, each beside its
  severity word. Snapshot deltas color only the `+`, `-` and `~` markers.
- Role colors mark state; words stay readable. In the lookup panel, source
  status, exposure, gaps and delta views, a role color sits on a marker (dots,
  source marks, the `!` warning mark) and the word that names the state stays
  in the default foreground, bold, or muted. Measured on Omarchy's tokyo-night
  (dark) and catppuccin-latte and flexoki-light (light) palettes, the default
  foreground reaches 7:1 or more everywhere and every role color reaches 5.4:1
  or more on the dark theme. On the light themes yellow measures 2.3:1 and
  green about 3:1, so they can mark state but cannot carry text there.
  Muted text, rendered faint by foot, measures 3.8:1 on tokyo-night, so muted
  is for repeated structure such as labels, never the only copy of a finding.
  `tests/test_theme_contrast.py` records the ratios and the known shortfalls.
- Color precedence, highest first: `--color` / `--no-color` (the last one
  given wins) > `NO_COLOR` (non-empty) > `TERM=dumb` > `FORCE_COLOR` (non-empty
  and not `0`) > terminal detection. Disabled color emits no escape sequence at
  all, on stdout and stderr.
- Functional glyphs have ASCII fallbacks, used under `--ascii`, `TERM=dumb`,
  or a terminal whose encoding cannot show them: `●●○` becomes `[##-]`, the
  source marks (check mark, dash mark, cross) become `ok`, `-` and `x`,
  `● ◐ ○` become `H M L`, and the divider becomes `-`. Any other glyph, such as a bullet, arrow, ellipsis, dash or box border,
  is transliterated, so ASCII mode output is pure ASCII.
- Confidence uses both a written level and the marker count; color alone does
  not communicate the level.
- Preserve one main divider, stable label alignment, and hanging continuation
  indentation. Text wraps at the actual console width; decorative rules do not
  wrap into extra rows. Ordinary wide output retains its established layout.
- Width rule: the lookup panel is laid out at `min(console width, 78)`, once.
  At 78 columns or more it is the established layout, so wide output does not
  change. Narrower, the sections are laid out again at the real width rather
  than laid out at 78 and re-wrapped, which is what left orphan words. Bordered
  panels (explanations, source status, posture, exposure, gaps, delta, chain)
  keep their 80-column box when the console has room and otherwise render flat,
  as a bold heading over the same body, so a border never folds or crops text.
- Identifiers never break. A UUID, hostname, URL, email address or path that
  does not fit moves to its own line at the value indent and may run past the
  edge; panels are printed with `crop=False` so it is not cut. Other text wraps
  between words, and only a word longer than a whole line is folded.
- Every value in a block starts in one column. The key-facts label column is
  the longest label present plus one, never less than the established 13 and
  never more than 16; a longer label puts its value on the next line at the
  value indent. Doctor rows use the same hanging indent: continuation lines
  start at the detail column, or the detail moves to an indented block when
  the name leaves too little room.
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
narrow-width content and style retention. `tests/test_narrow_layout.py` renders
the default, `--full` and `--explain` views at 40, 60, 80 and 120 columns and
checks that only a single identifier runs past the edge, that identifiers stay
on one line, that prose and key facts wrap once, that key-fact values share one
column and that doctor continuations start at the detail column; its 40 and 60
column golden renders sit beside the wide ones. `tests/test_exposure_visual_semantics.py`
pins neutral index styling. `tests/test_theme_roles.py` pins the role table,
color precedence and the ASCII fallback, and `tests/test_theme_contrast.py`
measures panel contrast on Omarchy palettes. `tests/test_caveat_parity.py`
renders a reserved and an ordinary name on every surface and asserts the same
qualifiers on each. `tests/test_cohort_display_semantics.py` checks
units, denominators and unavailable values. `tests/test_mcp_collection_notes.py`
keeps material CT caveats aligned across interfaces. The generated terminal
demo and existing golden renders remain independent integration gates.
