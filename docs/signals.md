# Signals

Signals are derived observations: "when these slugs show up together, emit this
line". They're defined in `recon_tool/data/signals.yaml`.

- **39 built-in signals** as of v1.0.2.
- **Two evaluation passes** — simple signals first, then meta-signals that
  depend on other signals firing (`requires_signals`). No third pass, no
  absence engine firing by default: `expected_counterparts` is available for
  user customisation but no built-in signal uses it.
- **Additive only** — custom signals in `~/.recon/signals.yaml` extend; they
  cannot override built-ins.

## Design rules

A signal must describe *something observable from DNS*. The tool retires
signals that drift into narrative judgment. Cut examples from recent
versions:

- `Shadow IT Risk` — framed sanctioned enterprise SaaS as "risk".
- `Complex Migration Window` — inferred a timeline the tool can't observe.
- `Governance Sprawl` — depended on `Shadow IT Risk`.
- `Security Stack Without Governance` — opinion that security investment
  should extend to email.
- `AI Adoption Without Governance` — speculated "shadow AI deployment".
- `DevSecOps Investment Without Email Governance` — same pattern.

If a proposed signal couldn't be rephrased as a factual observation, it
doesn't ship.

## Custom signals

Drop a `signals.yaml` in `~/.recon/`. Invalid entries are skipped with a
warning. Example:

```yaml
signals:
  - name: Healthcare Compliance Stack
    category: Vertical
    confidence: medium
    description: HIPAA-adjacent tooling detected
    requires:
      any: [okta, crowdstrike, proofpoint, knowbe4, 1password]
    min_matches: 3
```

Run `recon <your-domain> --explain` after adding to see whether it fires
and what evidence backed it.

## Expected counterparts (absence detection)

If you set `expected_counterparts: [slug-a, slug-b]` on a signal, the
absence engine emits a `{signal name} — Missing Counterparts` line for any
listed slug that doesn't appear in the detected set.

No built-in signal uses this. It exists for user customisation. Use
sparingly — expected-counterparts lists that name competing alternatives
(e.g. Proofpoint vs Mimecast vs Barracuda) produce noise, not insight.

```yaml
signals:
  - name: My Custom Signal
    category: Custom
    confidence: medium
    requires:
      any: [tool-a, tool-b]
    min_matches: 1
    expected_counterparts: [companion-x, companion-y]
```

## Full signal list

See `recon_tool/data/signals.yaml` directly — it's the source of truth
and shorter than any derived table.
