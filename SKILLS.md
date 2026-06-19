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
- When agent documentation mentions MCP approval, keep the stateful tool split
  explicit: ephemeral fingerprint mutation and data reload are session-local
  mutations even though most recon tools are read-only.
- Track external spend explicitly. Default spend is 0 USD.
- Before closing a cycle, run the narrow relevant gate. Before claiming repo
  readiness, run `uv run python scripts/check.py`.
