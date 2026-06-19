# Maintainer Loop Skills

This is a local agent learning artifact for this repository. It records reusable
operating rules for future cycles and must not override `AGENTS.md`,
`CONTRIBUTING.md`, or `docs/agentic-balance.md`.

## recon Operating Rules

- Treat `docs/agentic-balance.md` as the boundary document for any rule or
  agentic workflow.
- Keep agentic work outside the observe-infer-report core.
- Prefer deterministic gates over prose review.
- Do not add stable public surfaces without a concrete consumer and a
  compatibility story.
- When the private corpus is unavailable, support the calibration path with
  public-tree docs, guards, tests, or runbooks rather than inventing unrelated
  runtime features.
- Treat publishable validation memos as a disclosure boundary: target-looking
  strings can appear as values, keys, or free-form titles, so check all three.
- For paper or assurance reproducibility, add orchestration around existing
  harnesses rather than copying their logic. The orchestrator should capture
  commands, stdout, stderr, duration, success state, and what remains outside the
  public no-private-data path.
- When agent documentation mentions MCP approval, keep the stateful tool split
  explicit: ephemeral fingerprint mutation and data reload are session-local
  mutations even though most recon tools are read-only.
- When an agent only needs recon capability context, read MCP resources
  (`recon://fingerprints`, `recon://signals`, `recon://profiles`, or
  `recon://schema`) before any domain-analysis tool call.
- When a generated inventory is meant to help agents, include both machine
  surfaces and the guidance surfaces that teach clients how to call them. Pin
  the generated approval model to live MCP annotations, not copied prose.
- For CLI surface docs, generate Markdown from the live Typer command tree and
  gate it in `scripts/check.py`; do not maintain command and flag tables by hand.
- For release notes about CLI command or flag changes, compare generated
  `docs/surface-inventory.json` files with
  `scripts/summarize_cli_surface_changes.py`; do not diff help output manually.
- For Scorecard work, prefer real controls that align with existing invariants.
  Do not add unpinned workflow dependencies or fake service integrations only to
  move the badge.
- For Bayesian tuning knobs, prefer committed data in `bayesian_network.yaml`
  with loader defaults and invariant tests over module-level engine constants.
  Keep behavior unchanged at default values and update trust docs in the same
  cycle.
- Track external spend explicitly. Default spend is 0 USD.
- Before closing a cycle, run the narrow relevant gate. Before claiming repo
  readiness, run `uv run python scripts/check.py`.
