# Current State Analysis

This is a maintainer and agent planning snapshot. It is not a runtime contract
and does not replace the canonical project documents. If this file disagrees with
`README.md`, `docs/roadmap.md`, `docs/agentic-balance.md`,
`docs/schema.md`, or `docs/mcp.md`, the canonical document wins and this file
should be corrected.

## Scope Reviewed

The markdown inventory covers 103 files across the repository root, `docs/`,
`validation/`, `agents/`, `examples/`, `packaging/`, and test documentation.
The load-bearing sources for this snapshot are:

- `README.md`
- `AGENTS.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `docs/roadmap.md`
- `docs/agentic-balance.md`
- `docs/engineering-practices.md`
- `docs/maintainer-validation.md`
- `docs/statistical-assurance.md`
- `docs/data-handling-policy.md`
- `docs/mcp.md`
- `docs/schema.md`
- `docs/operational-contract.md`
- `docs/assurance-case.md`
- `docs/traceability-matrix.md`
- `docs/limitations.md`
- `validation/README.md`
- `validation/v2.0-corpus-run-runbook.md`
- `agents/README.md`
- `agents/claude-code/skills/recon/SKILL.md`

## Product Shape

recon is a passive, zero-credential domain intelligence primitive. It observes
public DNS, certificate transparency, and unauthenticated identity-discovery
endpoints, then reports hedged observations about identity, email posture,
service fingerprints, cloud footprint, and related domains.

The installed product is local-first:

- CLI
- importable Python library
- JSON producer
- stdio MCP server

It is not a hosted service, scheduler, active scanner, vulnerability scanner, or
firmographic intelligence system.

## Current Release State

The project is past the expansion and lock phases:

- v1.0 established stable CLI and JSON contract discipline.
- v2.0 locked the schema and promoted the fusion surfaces.
- v2.1.x shipped assurance, drift, interval, mutation, traceability, and
  validation gates.
- v2.2.x shipped evidence-semantics diagnostics, MCP structured-output
  contract revision, CLI ergonomics, surface inventory generation, file-size
  ratchets, and public assurance proving-test closure.

The current active line is v2.2.x. The roadmap says the next work is
dependency-ordered, not date-driven.

## Hard Constraints

Every proposed change must stay inside this box:

- Passive only.
- Zero credentials, zero API keys, zero paid APIs.
- No active scans, port probes, zone transfers, or target TLS handshakes outside
  explicitly documented opt-in direct probes.
- No bundled ML models, embeddings, ASN data, GeoIP data, or aggregate
  intelligence database.
- No user-code plugin system.
- Output is hedged, neutral, provenance-backed, and never a maturity verdict.
- Public repository artifacts must not contain real apexes, organization names,
  tenant IDs, per-domain findings, or unsuppressed small strata.
- The deterministic observe-infer-report core cannot depend on agent judgment,
  learned weights, or network-dependent nondeterminism.

## Agentic Balance

The alignment rule is clear: recon may be consumed by agents, but recon does not
become an agent.

Allowed agentic behavior lives outside the deterministic core:

- release-readiness loops;
- CI failure triage;
- calibration orchestration;
- fingerprint proposal drafts;
- docs and context packaging from existing sources.

Those loops must have clear stop conditions, deterministic gates, bounded cost,
and human review for semantic changes. Agent output can propose, summarize, and
prepare. It cannot silently mutate CPTs, fingerprints, schemas, releases, or
distribution artifacts.

The project therefore should not add LLM calls, learned classifiers,
auto-written CPT updates, autonomous catalog mutation, hosted scheduling, or
agent memory inside runtime behavior.

## Validation State

The public tree already contains substantial assurance:

- local CI mirror via `scripts/check.py`;
- strict lint and typing;
- coverage gate above 80 percent;
- fingerprint validation;
- metadata coverage gate;
- validation hygiene guard;
- workflow pinning guard;
- generated surface inventory drift check;
- generated CLI surface reference drift check;
- no active experimental labels;
- file-size ratchet;
- mutation gate and interval coverage work;
- traceability matrix and assurance case;
- data-handling controls for aggregate validation memos.

Current local verification in this session:

- `uv run python scripts/check.py` passed.
- Coverage was 86.16 percent, above the 82 percent configured gate.
- Paid or cloud spend: 0 USD.

## Active Roadmap Queue

The highest-priority active work is:

1. Run the maintainer-local calibration bundle against the gitignored private
   corpus, render aggregate-only memos, and commit only disclosure-safe metrics.
2. Use the fingerprint and motif triage loop only as a reviewed proposal path
   backed by existing scan and gap outputs.
3. Keep `docs/surface-inventory.json` and `docs/cli-surface.md` as derived
   drift guards unless a concrete consumer needs a stable contract.
4. Treat the arXiv write-up as packaging and communication, off the critical
   path.

This checkout does not currently contain `validation/corpus-private/`, so item 1
cannot be completed end to end here without maintainer-local data. Work in this
environment should therefore support that queue rather than bypass it.

## Highest-Leverage Public-Tree Work

Given the absent private corpus, the best aligned public-tree work is to improve
the maintainer-local loop around the calibration bundle without changing runtime
behavior. That means:

- keep the private-corpus run as the source of truth;
- add only docs, runbooks, validation helpers, or tests that make the next
  private run easier and safer;
- avoid promoting new product surfaces until a concrete consumer exists;
- avoid feature work that enlarges the user-facing surface before the active
  validation queue is closed.

This preserves the roadmap priority order:

Correctness -> reliability -> explainability -> composability -> new features.

## Drift Closed In This Cycle

Three documentation drifts were found during the review and corrected:

- `AGENTS.md` now refers to the stable v2.0 JSON contract instead of the old
  v1.0 wording.
- `docs/mcp.md` now reflects the read-only versus stateful MCP split in the
  Claude Code plugin approval note.
- `docs/limitations.md` now matches the README and legal docs on target-owned
  infrastructure: no host or application probing, with the documented MTA-STS
  default fetch and opt-in CSE / BIMI VMC direct probes.

One disclosure-boundary hardening also shipped in the public tree:

- `validation/render_calibration_memo.py` rejects target-looking domain names in
  aggregate JSON keys and memo titles, not only JSON values.

## Reproducibility Entry Point

The public, no-private-data paper-number rows now have a one-command entry
point:

```bash
python -m validation.reproduce_paper_numbers
```

The command writes local, gitignored artifacts under
`validation/local/paper-numbers/<UTC-stamp>/`, including a manifest, summary, and
per-harness outputs. The default `paper` profile runs the full public synthetic
and proof bundle. `--profile smoke` validates the orchestrator quickly. Private
corpus calibration remains maintainer-local.

## Agent Surface Inventory

`docs/surface-inventory.json` remains a generated, non-contractual drift guard.
It now inventories the local agent integration surface alongside the CLI, MCP,
and JSON-schema surfaces:

- portable and client-specific guidance files;
- Claude Code skill frontmatter;
- committed client MCP config templates;
- Claude Code plugin manifest metadata;
- live MCP read-only versus stateful approval sets.

The generator derives approval semantics from MCP annotations, so a new stateful
tool or annotation change must update both the generated inventory and its tests.

## CLI Surface Reference

`docs/cli-surface.md` is now a generated, non-contractual command and flag
reference. It is derived from the same live Typer command tree as
`docs/surface-inventory.json`, checked by `scripts/check.py`, and intended for
maintainers, skill authors, and agent prompts that need current CLI usage without
copying README snippets.

`scripts/summarize_cli_surface_changes.py` compares two generated surface
inventories and emits the one-line `### Tool Surface Changes` changelog entry
required by `docs/release-process.md`. It supports `--old-ref vX.Y.Z` for local
tag comparisons without shell redirection.

## MCP Resource Consumption

`docs/mcp.md` now includes no-network consumption examples for
`recon://fingerprints`, `recon://signals`, `recon://profiles`, and
`recon://schema`. The examples tell agents to inspect capability context before
network-capable domain analysis, to omit posture profiles when the target type
is unclear, and to treat a missing fingerprint as "no published fingerprint,"
not as evidence that a service is absent.

## Automation Parser Examples

`docs/automation-examples.md` now gives scripts a concrete consumption guide for
the existing JSON modes: single lookup, batch array, batch wrapper, NDJSON,
delta reports, and cohort summaries. The examples point consumers at exit-code
handling, `record_type` routing, schema validation, and unknown-field tolerance.

`examples/sample-output.json` now represents the full required v2.0 lookup
shape while preserving the fictional Northwind fields used by the SIEM examples.
`tests/test_automation_examples.py` parses the committed snippets and checks them
against the schema and runtime batch-record classifier.

## Verification Fingerprint Metadata

The verification-token catalog remains behavior-stable, but five high-confidence
entries now carry official public references: Monday.com, Zoom, Formstack, Coda,
and Virtru. Their regexes, confidence levels, and categories did not change.

The advisory metadata-richness audit now recognizes the catalog's
`account-binding`, `program-binding`, and `tenant-binding` wording as scope
narrowing. That aligns the audit with the wording already used to keep
verification-token signals hedged.

## Scorecard Posture

The public Scorecard API result checked on 2026-06-19 reported score 6.1 for
`github.com/blisspixel/recon` at commit `fc976bcab492232eb35111a26ea8deb14aa00b7e`.
The repo already scores 10 on dependency updates, security policy, dangerous
workflows, token permissions, SAST, binary artifacts, pinned dependencies,
vulnerabilities, packaging, and license.

Local-file work can improve future release posture most directly through the
Signed-Releases path. The release workflow now waits for build-provenance
attestation, exports the signed GitHub attestation bundles as
`recon-tool-<version>.intoto.jsonl`, and attaches that provenance asset to the
GitHub Release. The remaining low scores require external or policy choices:
branch protection and code-review settings, elapsed repository age, outside
contributors, OpenSSF Best Practices badge enrollment, and a real
Scorecard-recognized fuzzing service rather than a badge-only wrapper around
the existing Hypothesis suites.

## Bayesian Calibration Data

The n_eff interval calibration knobs now live in
`src/recon_tool/data/bayesian_network.yaml` under a top-level `calibration:`
block:

- `min_n_eff`
- `evidence_n_eff_contrib`
- `conflict_n_eff_penalty`

`load_network()` reads the block into `BayesianNetwork.calibration`, defaults
older fixtures to the current values, and validates every value as positive and
finite. The inference engine and conflict provenance use the loaded values, so
future interval tuning can be reviewed as data while keeping default behavior
unchanged.

## Decision Rule For The Next Task

When choosing work in the public checkout:

1. Prefer items that make the private calibration run more repeatable,
   reviewable, or disclosure-safe.
2. Prefer deterministic gates over agent prose.
3. Prefer generated or clearly marked snapshot artifacts over duplicate sources
   of truth.
4. Do not add a stable command, MCP resource, or schema field unless there is a
   named consumer and a compatibility policy.
5. Keep spend at 0 USD unless the user explicitly approves a paid step, and never
   exceed the 5 USD lifetime cap.
