# Agentic UX validation harness

**Audience:** recon maintainers running bridge-milestone validation for
the v1.9.x to v2.0 schema lock. End users running `recon example.com` do
not need this directory and do not need an LLM API key. The default
recon CLI never calls an LLM.

## What this exists for

The roadmap (`docs/roadmap.md` → v1.9.2) states that one of recon's
primary user personas *is* the AI agent: the MCP server is a real
production surface, and an agent reading recon JSON is a first-class
consumer. v1.9.2 is the bridge milestone that validates whether the
v1.9 fusion fields (`posterior_observations`, `slug_confidences`,
model-relative uncertainty bands, `sparse=true` flags) are actually used by
that audience, meaning whether agents read them, cite them, and let them
change a conclusion.

The harness drives three persona prompts (security analyst,
due-diligence researcher, ops engineer) across two committed fixtures
(`synthetic-dense.json` for a populated lookup; `synthetic-sparse.json`
for a deliberately-thin lookup) under fusion-on and fusion-off arms,
records transcripts, scores them against five binary checks, and
produces a self-contained markdown report under the gitignored
`validation/agentic_ux/local/` directory. The sanitized historical
aggregate at `validation/v1.9.2-agentic-ux.md` records the original
schema-lock disposition without retaining transcripts or target rows.

## Why it makes recon better

The harness produces *evidence* for or against design choices that
otherwise rely on intuition:

- Whether a posterior field is read or skipped under each persona's
  framing.
- Whether `sparse=true` actually causes an agent to hedge, or whether
  it gets parsed into the JSON tree and ignored.
- Whether the affordance to escalate (`--explain-dag`,
  `explain_dag` MCP tool) is discoverable from the JSON alone.

Each finding maps to a concrete v2.0 decision: keep the field as is,
rename, de-emphasize in the panel, expose a pointer field, or drop.
Without the harness, those decisions would be guesses. With it, they
are falsifiable.

## When to run it

- Before a v1.9.x bridge patch that proposes a schema-affecting
  change to fusion output. The harness baseline tells you which
  fields the change is moving.
- Before v2.0 schema lock, with at least two providers, so the
  finding pattern isn't single-vendor specific.
- When evaluating a new persona shape (e.g. when designing the v2.1
  closed-loop fingerprint-mining UX).

## What you need

1. The optional SDK for whichever provider you want:
   ```bash
   pip install anthropic   # for --provider anthropic (default)
   pip install openai      # for --provider openai or xai
   ```
   These are NOT runtime dependencies of recon; they are dev
   dependencies of this harness only.
2. The matching API key in your environment:
   - `ANTHROPIC_API_KEY` for Anthropic
   - `OPENAI_API_KEY` for OpenAI
   - `XAI_API_KEY` for xAI Grok
3. The fixtures and personas in this directory (already committed).

## Running it

```bash
# Default provider and model, with provider charges
python -m validation.agentic_ux.run

# Lower-cost model option
python -m validation.agentic_ux.run --model claude-haiku-4-5

# OpenAI
python -m validation.agentic_ux.run --provider openai --model gpt-5

# xAI Grok
python -m validation.agentic_ux.run --provider xai --model grok-4

# Subset of personas / fixtures
python -m validation.agentic_ux.run --personas analyst,ops --fixtures synthetic-dense
```

The runner writes the report to
`validation/agentic_ux/local/report.md` by default. `--output` and
`--records-json` accept paths outside the repository or under the
gitignored `validation/agentic_ux/local/` and
`validation/agentic_ux/runs/` directories. Other in-repository paths
are rejected before provider initialization.

## Privacy and data discipline

Everything in this directory respects the project's
no-real-company-data invariant (see `validation/README.md` →
Policy):

- Both fixtures use explicit synthetic identities under the reserved
  `.invalid` namespace.
- Persona prompts and neutral fixtures are committed. Transcripts,
  provider metadata, and raw run records stay local and gitignored.
- API keys never get committed. The harness reads them from env or
  from a `--api-key` argument; it does not log them and does not
  embed them in the report.
- Keep every run output under `validation/agentic_ux/runs/` or
  `validation/agentic_ux/local/`, both of which are gitignored.

## What this is NOT

- **Not a runtime dependency of recon.** The default recon CLI does
  not call an LLM, does not require any API key, and does not
  import this directory.
- **Not a replacement for human operator interviews.** The roadmap
  v1.9.2 milestone keeps human interviews as a future option; the
  agentic harness is one persona class (the AI-agent persona),
  validated reproducibly. A SOC analyst clicking through the CLI
  is a different signal that this harness does not capture.
- **Not autonomous self-improvement.** The harness measures; humans
  decide. The findings are recommendations to a human curator, not
  auto-applied changes to recon's behavior.
