# Agentic UX runbook for v1.9.9 surfaces

The v1.9.2 agentic UX harness at `validation/agentic_ux/run.py`
validates that AI agents read the panel correctly. v1.9.9 added two
new panel surfaces (Multi-cloud rollup, Passive-DNS ceiling) that
the v1.9.2 evidence does not cover. This runbook is the
maintainer's recipe for re-running the harness against v1.9.9
panels with the smallest LLM footprint and clearest output.

The harness needs an LLM API key; recon itself does not. Keep the
operational boundary clean.

## Smallest-cost invocation

The default harness runs 3 personas × 2 fixtures × 2 fusion modes
= 12 sessions × ~2K tokens each. To minimize cost while still
covering the v1.9.9 surfaces, run a focused subset:

```bash
# One persona (analyst) × multi-cloud-firing fixture × fusion-on
# Anthropic Claude Haiku 4.5 is the cheapest current model that
# remains useful for instruction-following at this scale.
python -m validation.agentic_ux.run \
    --provider anthropic \
    --model claude-haiku-4-5-20251001 \
    --personas analyst \
    --fixtures contoso-dense \
    --max-tokens 1024 \
    --output validation/v1.9.9-agentic-ux-update.md
```

Rough cost envelope (Haiku 4.5 input ~$1/M tokens, output ~$5/M):
- 1 persona × 1 fixture × 2 modes = 2 sessions
- ~3K input tokens + ~1K output tokens per session
- Total ~6K input + 2K output = ~$0.016 per run

Compared to the full default matrix (~$0.10 per run on Haiku, more
on Sonnet/Opus), the focused subset is ~6× cheaper.

## What to look for in the output

The harness produces transcripts and a per-persona scoring table.
The v1.9.9-specific questions to add to the rubric:

1. **Did the agent read the Multi-cloud row?** The row appears in
   the key-facts block above Confidence on the contoso-dense
   fixture (Azure DNS + Akamai surface attribution = 2 vendors).
   The agent should cite "Azure" and "Akamai" or "two cloud
   vendors" in its analysis.
2. **Did the agent treat the Multi-cloud signal as evidence?**
   On a multi-cloud apex, the agent should mention the multi-vendor
   nature when describing the footprint, not skip it.
3. **Does the agent mistake the ceiling footer for an error?** The
   footer reads as a teaching note ("Passive DNS surfaces what
   publishes externally..."). The agent should treat it as
   architectural context, not as a tool failure or a sparse-data
   warning the operator should act on.

The hardened-sparse fixture has `display_name: null` and does not
load via the cache deserializer; skip it for the v1.9.9 update or
fix the loader contract first.

## Expanding the matrix later

When budget allows, expand to:

```bash
# All three personas, both fixtures, both modes — full v1.9.2
# methodology re-run on v1.9.9 panels.
python -m validation.agentic_ux.run \
    --provider anthropic \
    --model claude-sonnet-4-6 \
    --output validation/v1.9.9-agentic-ux-full.md
```

Rough cost envelope: ~$0.50–$1.00 per run on Sonnet 4.6.

## Why this is not run automatically

- LLM calls cost money and require API keys.
- The harness is a *human-supervised* validation step. Automated
  scoring is provided but a human should read at least one
  transcript per run to sanity-check the rubric output.
- The harness is the v1.9.2 contract; v1.9.9 surfaces are an
  additive enrichment, not a redesign. The risk that v1.9.9
  silently regresses agent UX is bounded by the existing
  agentic-UX fixture compatibility tests
  (`tests/test_agentic_ux_compatibility.py`), which already pin
  that v1.9.2 fixtures continue to load and render through v1.9.9.

## Related artifacts

- `validation/agentic_ux/README.md` — full harness documentation.
- `validation/synthetic_corpus/render_snapshots.md` — actual panel
  text for all 21 fixtures so the maintainer can preview what each
  agent will see.
- `validation/v1.9.2-agentic-ux.md` — the v1.9.2 baseline report.
