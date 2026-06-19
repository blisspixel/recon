# Progress Log

This file records maintainer-loop work performed in this checkout. It is a local
planning artifact and does not replace `CHANGELOG.md`.

## 2026-06-19

- Created the active goal for autonomous roadmap progress.
- Inventoried 103 markdown files across root docs, validation reports, agent
  integrations, examples, packaging, and test documentation.
- Confirmed `validation/corpus-private/` is absent in this checkout, so the
  top active roadmap item is blocked on maintainer-local private data.
- Initial full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.18 percent. Tests: 3363 passed, 5 skipped, 4 deselected.
- Created `CURRENT-STATE-ANALYSIS.md`, `PROGRESS-LOG.md`, and `SKILLS.md` as
  noncanonical maintainer-loop artifacts.
- Hardened `validation/render_calibration_memo.py` so the public memo boundary
  rejects target-looking domain names in aggregate JSON keys and memo titles.
- Added focused disclosure tests in `tests/test_render_calibration_memo.py`.
- Corrected low-risk doc drift in `AGENTS.md`, `docs/mcp.md`, and
  `docs/limitations.md`.
- Focused validation: `uv run python -m pytest tests/test_render_calibration_memo.py -q`
  passed with 10 tests.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.16 percent. Tests: 3365 passed, 6 skipped, 4 deselected.
- Started the second cycle from the roadmap's reference-grade repository track.
- Added `validation/reproduce_paper_numbers.py`, a one-command public
  no-private-data reproduction bundle for the paper's synthetic and proof
  evidence rows.
- Documented the command in `validation/README.md`, `docs/roadmap.md`,
  `docs/paper-outline.md`, and `docs/paper-draft.md`.
- Added `tests/test_reproduce_paper_numbers.py` covering manifest output,
  dry-run behavior, failure handling, and profile validation.
- Ran the smoke profile:
  `uv run python -m validation.reproduce_paper_numbers --profile smoke --stamp smoke-test`.
  It passed and wrote ignored artifacts under `validation/local/`.
- Focused validation: `uv run python -m pytest tests/test_reproduce_paper_numbers.py tests/test_render_calibration_memo.py -q`
  passed with 14 tests.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.15 percent. Tests: 3370 passed, 5 skipped, 4 deselected.
- Started the third cycle from the agent and surface-inventory drift guard
  track.
- Extended `scripts/generate_surface_inventory.py` so
  `docs/surface-inventory.json` now includes agent guidance files, client MCP
  config templates, Claude Code plugin manifest metadata, and live MCP approval
  sets derived from tool annotations.
- Corrected the Claude Code plugin approval note so it no longer claims every
  MCP tool is read-only. It now names the three local stateful tools and
  describes the read-only split.
- Added `tests/test_surface_inventory.py` coverage for agent guidance
  frontmatter, client config keys, manual approval defaults, and the stateful
  MCP tool set.
- Focused validation:
  `uv run python -m pytest tests/test_surface_inventory.py tests/test_mcp_tool_annotations.py -q`
  passed with 8 tests.
- Focused lint:
  `uv run python -m ruff check scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.17 percent. Tests: 3371 passed, 5 skipped, 4 deselected.
- Started the fourth cycle from the roadmap's no-behavior-change Bayesian
  calibration data item.
- Added a top-level `calibration:` block to
  `src/recon_tool/data/bayesian_network.yaml` for `min_n_eff`,
  `evidence_n_eff_contrib`, and `conflict_n_eff_penalty`.
- Added `CalibrationSettings` to the loaded Bayesian network, with loader
  defaults for older test fixtures and strict positive finite validation.
- Updated inference and conflict provenance to use the loaded network
  calibration values while preserving the historical module constants for
  internal compatibility.
- Updated roadmap, correlation, traceability, mutation-gate, and validation
  helper docs so they describe the YAML-backed calibration shape.
- Focused validation:
  `uv run python -m pytest tests/test_bayesian_inference.py tests/test_bayesian_unit_math.py tests/test_bayesian_network_invariants.py tests/test_bayesian_hypothesis.py tests/test_bayesian_fuzz.py tests/test_bayesian_masked_units.py tests/test_adversarial_properties.py tests/test_bayesian_sensitivity.py -q`
  passed with 178 tests.
- Focused lint and traceability:
  `uv run python -m ruff check ...` passed, and
  `uv run python scripts/check_traceability.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.18 percent. Tests: 3376 passed, 6 skipped, 4 deselected.
- Started the fifth cycle from the roadmap's downstream skill and agent-author
  surface-reference item.
- Added generated `docs/cli-surface.md`, derived from the live Typer command
  tree with command anchors, child command lists, and parameter tables.
- Extended `scripts/generate_surface_inventory.py` with `--write-cli-surface`
  and `--check-cli-surface`, keeping the Markdown reference generated rather
  than manually maintained.
- Added `scripts/check.py` coverage for the CLI surface reference through a new
  `cli-surface-doc` stage.
- Updated README, docs index, roadmap, and changelog so the generated CLI
  reference is discoverable and the roadmap marks that part of the surface
  inventory work done.
- Added `tests/test_surface_inventory.py` coverage for CLI surface freshness,
  expected command content, ASCII output, and target-free output.
- Focused validation:
  `uv run python -m pytest tests/test_surface_inventory.py -q` passed with 9
  tests.
- Focused lint and generated-file checks passed:
  `uv run python -m ruff check scripts/generate_surface_inventory.py tests/test_surface_inventory.py scripts/check.py`
  and `uv run python scripts/generate_surface_inventory.py --check --check-cli-surface`.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.14 percent. Tests: 3380 passed, 5 skipped, 4 deselected.
- Started the sixth cycle from the remaining CLI surface release-note polish.
- Added `scripts/summarize_cli_surface_changes.py`, a maintainer-local comparer
  for generated `docs/surface-inventory.json` files that emits the
  changelog-ready `Tool surface changes:` line.
- The helper supports direct inventory paths, `--old-ref vX.Y.Z` for git-tag
  comparisons without shell redirection, and `--json` for structured release
  automation.
- Added `tests/test_summarize_cli_surface_changes.py` covering command deltas,
  flag deltas, no-change summaries, JSON output, argument validation, and git
  ref failures.
- Updated `docs/release-process.md` to require a `### Tool Surface Changes`
  entry per release and to document the helper.
- Updated `CHANGELOG.md` with the current no-runtime-CLI-change surface line and
  `docs/roadmap.md` to mark the CLI surface inventory release-note item done.
- Focused validation:
  `uv run python -m pytest tests/test_summarize_cli_surface_changes.py -q`
  passed with 7 tests.
- Focused lint:
  `uv run python -m ruff check scripts/summarize_cli_surface_changes.py tests/test_summarize_cli_surface_changes.py`
  passed.
- Helper smoke:
  `uv run python scripts/summarize_cli_surface_changes.py --old-ref HEAD`
  returned `Tool surface changes: no CLI command or flag changes.`
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.16 percent. Tests: 3387 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
