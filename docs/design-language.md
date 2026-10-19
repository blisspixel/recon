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
- Preserve useful content and styles at 40, 60 and 80 columns. Exercise long
  identifiers and wide Unicode characters. Do not hide missing text by changing
  a golden rendering to match a defect.
- Honor automatic terminal detection and the existing color overrides. Piped
  structured data must remain separate from diagnostics on stderr.

## Motion

recon has one moving element, the source ladder, and it lives on stderr only
(`src/recon_tool/cli/source_ladder.py`, state and wording in
`src/recon_tool/formatter/source_ladder.py`).

- While a human lookup collects, the ladder shows one row per source family:
  DNS records, Microsoft tenant discovery, Microsoft user realm, Google
  identity, MTA-STS policy and certificate transparency. A running row shows a
  braille spinner in the success role; it settles to a check mark and
  `matched`, a dash mark and `no match`, or a cross and
  `unavailable (reason)`, with the ASCII marks `ok`, `-` and `x`. A row changes only when the resolver reports that source's result.
- When collection ends, the rows are erased and one source-health line takes
  their place above the panel, for example
  `6 sources: 3 matched, 2 no match, 1 unavailable (CT: crt.sh rate limited)`.
  Counts are per collection unit, zero counts are omitted, and reasons come
  from a fixed vocabulary (`timeout`, `could not resolve`, `rate limited`,
  `HTTP 503`), never from collector text.
- Each frame is written inside synchronized output (DEC mode 2026), at most 12
  frames per second, from one task that sleeps between frames. Events update
  state but never draw. Once collection settles the task is awaited, so a
  finished ladder costs no CPU.
- Animation is off under `--no-color`, `NO_COLOR`, `TERM=dumb`, `CI`,
  `RECON_NO_ANIMATION=1`, `--debug`, a legacy Windows console, and whenever
  stderr is not a terminal. The source-health line alone is the static form.
  `--json`, `--md` and `--explain-dag` show neither.
- Diagnostics never print through the live region. Collector warnings are
  captured during collection and summarized once, after the ladder collapses:
  `2 hosts could not be resolved (...). Run recon doctor.` Name a condition by
  what it is: an unresolved name `could not resolve`, a refused destination
  `skipped: resolves to a private address (10.0.0.5)`.

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
pins neutral index styling. `tests/test_theme_roles.py` pins the role table,
color precedence and the ASCII fallback, and `tests/test_theme_contrast.py`
measures panel contrast on Omarchy palettes. `tests/test_source_ladder.py`
pins the frame cap, the idle-after-settle rule, every animation off switch and
the health-line counts, and `tests/test_collection_warnings.py` pins the
warning summary and the resolver wording. `tests/test_cohort_display_semantics.py` checks
units, denominators and unavailable values. `tests/test_mcp_collection_notes.py`
keeps material CT caveats aligned across interfaces. The generated terminal
demo and existing golden renders remain independent integration gates.
