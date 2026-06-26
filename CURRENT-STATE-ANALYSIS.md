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

The current active line is v2.2.x; v2.2.14 is the current release (2026-06-26:
boundary-aware hostname matching for Google identity routing and IdP display
names, plus Exchange Online DKIM attribution by hostname suffix). The roadmap
says the next work is dependency-ordered, not date-driven.

## Schema Generator Drift Gate

The schema-generation backlog is now closed for the top-level JSON contract.
`scripts/generate_schema.py --check` derives the generated property set from
`recon_tool.schema_contract.REQUIRED_TOP_LEVEL_FIELDS` plus explicit
conditional-field metadata, verifies every property against the existing
`TenantInfo` source-map audit, and checks both published schema copies. The
generator deliberately preserves the existing human-written descriptions,
constraints, compact formatting, and nested `$defs`; the current best-practice
reading is to keep JSON Schema as a declarative contract with reviewed
annotations while making the code-owned field set mechanically checked.

## Surface Inventory Promotion Decision

ADR-0007 keeps `docs/surface-inventory.json` and `recon://surface-inventory` as
generated discovery context, not a stable runtime API contract. The code already
packages the resource and gates drift; the missing ingredient for a 2.3 stable
surface is not machinery, it is a concrete external consumer that needs a
minimal, versioned subset with compatibility promises. Until then, the inventory
remains patch-level and non-contractual.

## C3 CT Partial Session Recovery

The first CT-enabled C3 corpus session on 2026-06-26 produced a useful partial
NDJSON stream before an outer process timeout stopped the wrapper. The recovered
aggregate is documented in `validation/2026-06-26-c3-ct-partial.md`: 2,693 valid
records out of 5,241, with CT mostly blocked by the local breaker. This does not
complete C3 and does not change the Bayesian calibration claims; it confirms the
roadmap's multi-session CT framing.

The maintainer tooling now supports the correct operational shape:

- `recon batch --timeout` bounds each domain in batch mode.
- `validation/scan.py --max-runtime` stops a session deliberately and finalizes
  parseable NDJSON records.
- `validation/scan.py --finalize-existing` recovers aggregate artifacts from an
  already-streamed run directory without network calls.
- Partial metadata records valid parseable records, timeout settings, and
  completion state, and partial scans skip noisy diffs.
- Controlled timeouts terminate the batch process tree on Windows so a launcher
  process cannot leave a child interpreter writing after the wrapper exits.

## Profile signal_boost Correctness Fix (2.2.13)

The profile engine's `signal_boost` and `exclude_signals` were inert since they
shipped: the keys were matched against rendered statement text, and the six
built-in profiles keyed them by `signals.yaml` display names, while
`apply_profile` only ever reweights `posture.yaml` observations. `Observation`
now carries `source_name` (its originating posture rule), `apply_profile` matches
the boost and exclude keys against it (`exclude_signals` keeps the statement
substring fallback for custom profiles), and the built-in profiles were remapped
to the posture rule names that are the direct equivalents of their old signal
keys. `tests/test_profiles.py` now guards that every built-in profile key names a
real posture rule, so stranded config cannot ship again. This shifts `--profile`
salience and ordering where a boosted rule fires; the JSON schema, profile YAML
field set, and CLI surface are unchanged.

## Text-Hygiene Local/CI Parity Fix (2.2.13)

`scripts/check_text_hygiene.py` ran git in text mode without an explicit
encoding, so on Windows it decoded git's UTF-8 diff output as cp1252 and missed
an em dash that CI (UTF-8) caught. `_run_git` now decodes as UTF-8, with a
regression test that builds a temp git repo with an em-dash line and asserts the
checker flags it through the previously-untested git-diff path. Maintainer
tooling only; no runtime change.

## Boundary-Unaware Substring Hardening (v2.2.14)

A sweep for the boundary-unaware-substring bug class (a vendor host matched as a
raw substring of a URL or DNS value rather than by hostname suffix) found two
safe-to-fix instances and several core-detection candidates that need their own
validation:

- `_extract_idp_name` in `sources/google.py` and `sources/google_identity.py`
  now parses the URL hostname and matches IdP vendors by exact host or dotted
  suffix, so a lookalike host or a vendor name in a path or query no longer
  matches. Display-name only.
- `GoogleIdentitySource._is_federated_redirect` now parses the final URL and
  checks the hostname against `google.com` by exact host or dotted suffix before
  reading SAML/SSO handoff indicators. A lookalike host such as
  `evilgoogle.com`, or a `google.com` string in a path or query, no longer
  changes the Google-vs-third-party routing decision.
- `_apply_exchange_dkim` in `sources/dns_email.py` now matches `onmicrosoft.com`
  and `protection.outlook.com` by hostname suffix. Validated against existing
  maintainer-local corpus evidence (aggregate-only): the substring form produced
  2 non-suffix false-positive shapes out of 825 hostname-shaped evidence values.
  Suffix matching keeps every true positive. Memo:
  `validation/2026-06-26-onmicrosoft-suffix-match.md`.

The shared `validator.host_has_suffix()` helper now owns the exact-host or
dotted-suffix predicate used by these fixes. That keeps hostname-boundary logic
in one tested place and avoids growing parallel local helpers in detector code.

2026 best-practice refresh for this task: hostname decisions should be made on a
parsed authority component, then checked against an explicit allowlist or
suffix boundary. This matches OWASP SSRF guidance around strict destination
validation and Python's `urllib.parse` warning that URL parsing does not itself
validate a URL. The repo-local consequence is narrow: `urlparse()` is used only
to extract the hostname, and `host_has_suffix()` plus negative tests enforce the
security boundary.

The remaining candidates (the GWS DKIM `google.com` fallback and the
`outlook.com` / SRV-based `lync.com` / `teams.microsoft.com` checks in
`sources/dns_infra.py`) were validated against the same corpus evidence and
showed zero non-suffix matches (`outlook.com` 303/303, `google.com` 757/757 clean
suffixes; the SRV patterns had no evidence occurrence). They are left unchanged
per the mirror-not-fitter discipline: detection is tightened only on a
demonstrated false positive, which only `onmicrosoft.com` showed.

## Quality Rubric

`QUALITY-RUBRIC.md` is the maker-checker scorecard for this checkout: six
categories (correctness, security/supply chain, performance, readability,
maintainability, sustainability/invariants), each scored 1 to 5, all required at
5 to ship. It references `docs/engineering-practices.md` as the canonical
standard rather than duplicating it, and names `uv run python scripts/check.py`
as the gate that proves most of the rubric.

Current maintainer-loop deltas from 2026-06-19 include generated surface
inventory checks, the `recon://surface-inventory` local discovery resource,
PR-scoped ClusterFuzzLite parser-boundary fuzzing, public paper-number
reproduction tooling, shared validation-runner path-containment hardening,
calibration corpus-shape preflight, the optional maintainer-loop runbook,
nested schema drift hardening, advisory diff coverage, local-stack commit
hygiene, the PLR size-rule ratchet, cache edge coverage, high-value-target
baseline expectations, and a first production `match_mode: all` fingerprint for
CrowdStrike TXT evidence. The public
catalog-growth queue also now includes a Supabase CNAME target sourced from the
official custom-domain docs, with the generic ACME TXT challenge deliberately
kept out of scope. The motif queue now includes a complete Microsoft internal
triad motif for Traffic Manager to Azure Front Door to Microsoft Edge chains,
with a public candidate-chain delta. The MCP precise-schema Phase 2 now covers
with `TypedDict` output item schemas for the no-network catalog tools, the
signal explanation tool, the simple ephemeral-fingerprint session tools, the
graph data tools, the compact agent-facing posture helpers, and the posterior
readout, exposure report tools, discovery candidate list, posture analysis
variants, and cached-domain re-evaluation lookup record.

The 2026-06-24 external best-practice refresh checked current MCP security and
tool-output guidance, OWASP agent and skill guidance, SLSA provenance levels,
and GitHub artifact-attestation guidance. No new runtime surface is warranted:
the local stdio MCP shape, deterministic core, data-not-instructions boundary,
manual approval posture, structured tool output, and signed-release track remain
aligned. The actionable public-tree gap was stale MCP launch guidance that still
made hand-written `python -m recon_tool.server` configs look normal. The
installer already emits a sys.path-stripping Python fallback when `recon` is not
on PATH; `doctor --mcp`, `doctor --client`, `docs/mcp.md`, agent setup docs, and
the Claude Code skill now describe and test that safer path.

The 2026-06-25 refresh rechecked PyPI PEP 740 attestations, OpenSSF Scorecard,
SLSA build requirements, and MCP local-server security guidance. The current
best reading is still deepen-not-expand: keep local and remote gates exact,
keep provenance and attestation checks fail-closed, and keep MCP command launch
behavior explicit. The cleanup from the remote-main push also simplified the
README license section to Apache 2.0 plus the LICENSE link only; release
readiness now guards that wording so the removed enterprise-contact sentence
does not drift back in.

The 2.2.14 release shipped on 2026-06-26. The release workflow passed, published
to PyPI, exported attestations, and created the GitHub release. PyPI JSON now
reports `recon-tool` 2.2.14 with `>=3.11`; the Homebrew formula has been
refreshed from that published sdist.

The 2026-06-25 fingerprint-triage pass re-filtered an old private gap run with
the current public catalog and committed only aggregate conclusions. A
sample-aware triage fix now checks candidate sample terminals and chain hops
against existing `cname_target` patterns, reducing false candidate work when a
three-label suffix bucket hides a more specific already-covered endpoint. The
same pass promoted public-source-backed surfaces for UltraDNS Web Forwarding via
`crs.ultradns.net` and Squarespace managed subdomains via
`ext-sq.squarespace.com`, leaving the remaining private aggregate candidates
unshipped pending stronger public vendor references or clearer non-target-owned
signal.

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

## Maintainer Loop Runbook

`docs/maintainer-loop-runbook.md` now turns the roadmap's optional loop idea into
a concrete maintainer contract for CI failure triage, private calibration, and
fingerprint proposal loops. Each loop must load the same context packet, write
state only to ignored local paths, name a deterministic gate, stop on pass or a
reproducible blocker, track spend from 0 USD, and leave semantic changes for
normal maintainer review. The runbook is documentation and guardrail only; it is
not a runtime scheduler or an agent inside recon.

## Schema Drift Guard

`tests/test_json_schema_file.py` now checks model-backed nested `$defs` against
their dataclass field sets, with explicit exceptions for fields that are not in
the stable JSON envelope. This does not replace the future schema generator, but
it closes the immediate risk that a nested model field moves without the
hand-maintained JSON Schema noticing.

`scripts/check_schema_sources.py` now adds the top-level companion guard. It
traces each `docs/recon-schema.json` property to a `TenantInfo` dataclass field
or an explicit formatter, static-envelope, batch-mode, or explain-mode source,
and it fails if a new `TenantInfo` field is left unrepresented without an
intentional omission. The full schema generator remains open, but the source
map now makes the generator inputs reviewable. The checker also has a JSON
report mode for local review of the source map, intentional omissions, and issue
lists before the full generator exists.

`docs/stability.md` now summarizes the current schema counts from
`docs/recon-schema.json`: 56 top-level properties and 47 required fields for a
single-domain success object. `tests/test_stability_docs.py` ties that summary
to the schema and live MCP tool registry, including the MCP stability table, so
the JSON and MCP surface counts do not drift again.

## Diff Coverage Signal

`scripts/diff_coverage.py` is now available as an advisory maintainer signal.
It reads Coverage.py JSON plus a unified diff, reports coverage only for changed
executable Python lines, optionally fails under a caller-supplied threshold, and
returns success for documentation-only diffs. It is intentionally outside
`scripts/check.py` so small docs changes do not inherit a per-PR coverage gate.

## Commit Hygiene

`scripts/release_readiness.py` now checks every commit in `origin/main..HEAD`
when the local branch is ahead, instead of only the latest message. The check
falls back to `HEAD` when there is no ahead stack and rejects attribution
markers, em dashes, and pictographic symbols before the maintainer relies on
remote CI.

## PLR Size-Rule Ratchet

`scripts/check_plr_ratchet.py` now runs in `scripts/check.py` as a fast core
stage. It tracks current `PLR0911`, `PLR0912`, `PLR0913`, and `PLR0915` counts
as ceilings, blocking new function-size debt while allowing the existing debt to
be reduced deliberately.

The file-size ratchet also tightened after the 2026-06-24 full gate reported
earned shrinkage: `exposure.py` is now capped at 981 lines and `merger.py` at
955 lines. `formatter.py` remains deliberately large and capped at its existing
2164-line ceiling.

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
- Coverage was 86.57 percent, above the 82 percent configured gate.
- Tests: 3550 passed, 5 skipped, 4 deselected.
- Focused MCP launch-guidance validation passed:
  `uv run python -m pytest tests/test_doctor.py tests/test_doctor_client.py tests/test_mcp_path_isolation.py tests/test_surface_inventory.py -q`
  with 53 passed and 2 skipped.
- Remote `main` verification for commit `6f71303` passed: CI, Secrets scan, and
  Scorecard supply-chain security all completed successfully.
- Full local gate for the README license-readiness guard passed:
  `uv run python scripts/check.py` with 3552 passed, 5 skipped, 4 deselected,
  and 86.57% total coverage.
- Full local gate for the private validation output-root guard passed:
  `uv run python scripts/check.py` with 3557 passed, 6 skipped, 4 deselected,
  and 86.57% total coverage.
- Paid or cloud spend: 0 USD.

## Active Roadmap Queue

The highest-priority active work is:

1. Calibration corpus runs: DONE (2026-06). The maintainer-local bundle ran
   against the private corpus at concurrency 2 (reference with held-out residual,
   tenancy corroboration, per-vertical stratification, conformal). Aggregates are
   in `validation/2026-06-23-full-corpus-calibration.md`; the honest reading
   (email-policy node strongly calibrated but DMARC-anchored with the clean
   residual disconfirmed; M365 tenancy corroborated) is folded into
   `validation/reference-calibration.md` and `docs/statistical-assurance.md`. The
   remaining optional pass is C3 (CT-enabled full corpus).
2. Use the fingerprint and motif triage loop only as a reviewed proposal path
   backed by existing scan and gap outputs.
3. Keep `docs/surface-inventory.json` and `docs/cli-surface.md` as derived
   drift guards unless a concrete consumer needs a stable contract.
4. Treat the arXiv write-up as packaging and communication, off the critical
   path.

The private corpus is maintainer-local (gitignored here, accessed from a separate
local copy for the run). Per the data-handling policy, only disclosure-safe
aggregates are committed; no apexes, organization names, tenant IDs, or per-domain
output leave the maintainer machine.

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
- Maintainer-local validation output roots now fail closed when they point
  inside the repository but outside the gitignored private validation
  workspaces. `validation/run_calibration_bundle.py` is restricted to
  `validation/runs-private/` for in-repo outputs, and `validation/scan.py`
  accepts only `validation/runs-private/`, `validation/live_runs/`, or
  `validation/local/` inside the checkout. Outside-repo operator-local paths
  stay allowed.
- The user-provided agentic development guide was useful as a maintainer-loop
  checklist, not as a product-surface expansion. The adopted pieces are now in
  `docs/agentic-balance.md` and `docs/maintainer-loop-runbook.md`: explicit
  action boundaries, resume keys for idempotent retries, trace records instead
  of raw model reasoning, and maintainer approval before externally visible
  release, distribution, schema, CPT, or catalog side effects.

## MCP Launch Guidance Alignment

The current MCP security posture is local-first and stdio-first. Local MCP
servers are executable code, so operator guidance should make the launched
command explicit and should avoid workspace-dependent import behavior when a
safer generated config is available. The installer path is now the source of
truth:

- `recon mcp install` prefers the `recon mcp` command when the script is on
  PATH.
- If the script is not on PATH, it writes a Python `-c` launcher that strips
  cwd-equivalent entries from `sys.path` before importing `recon_tool`.
- `recon doctor --mcp` emits that same generated fallback instead of a stale
  `python -m recon_tool.server` block.
- `recon doctor --client` warns when a client config uses the unisolated module
  launcher directly.
- Agent setup docs and the Claude Code skill now match the stable v2.0 schema
  contract and the installer behavior.

This is patch-level hardening. It does not change the runtime protocol,
fingerprint catalog, inference model, JSON shape, or MCP tool set.

## Reproducibility Entry Point

The public, no-private-data paper-number rows now have a one-command entry
point:

```bash
python -m validation.reproduce_paper_numbers
```

The command writes local, gitignored artifacts under
`validation/local/paper-numbers/<UTC-stamp>/`, including a manifest, summary, and
per-harness outputs. The default `paper` profile runs the full public synthetic
and proof bundle. `--profile smoke` validates the orchestrator quickly. Its
optional `--stamp` is validated as a single safe path segment before artifact
paths are resolved under the output root. Private corpus calibration remains
maintainer-local, but the bundle now performs a local preflight before any
network harness starts: the consolidated corpus must meet the configured
`--min-cell`, at least one stratum file must be publishable, and dry runs report
eligible and suppressed strata.

## Agent Surface Inventory

`docs/surface-inventory.json` remains a generated, non-contractual drift guard.
It now inventories the local agent integration surface alongside the CLI, MCP,
and JSON-schema surfaces:

- portable and client-specific guidance files;
- Claude Code skill frontmatter;
- committed client MCP config templates;
- Claude Code plugin manifest metadata;
- live MCP read-only versus stateful approval sets;
- the maintainer-loop context packet, with file roles and path-existence
  checks for `README.md`, `AGENTS.md`, `docs/agentic-balance.md`,
  `docs/roadmap.md`, `docs/maintainer-validation.md`, `validation/README.md`,
  `PROGRESS-LOG.md`, and `SKILLS.md`.

The generator derives approval semantics from MCP annotations, so a new stateful
tool or annotation change must update both the generated inventory and its
tests. The context-packet entry is likewise generated discovery context, not a
stable API contract.

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

## Supabase Surface Fingerprint

The catalog now includes a high-confidence Supabase `cname_target` rule for
project hostnames under `supabase.co`, sourced from the official custom-domain
docs. The rule is intentionally scoped to routing evidence for a branded
subdomain and does not infer project plan, database contents, or account
control.

The same docs also describe `_acme-challenge` TXT validation, but that value is
generic ACME evidence rather than a Supabase-specific token. The catalog keeps it
out of scope unless a future vendor flow publishes a stable vendor-specific TXT
shape.

## UltraDNS Web Forwarding Fingerprint

The catalog now includes a high-confidence UltraDNS `cname_target` rule for
`crs.ultradns.net`, sourced from UltraDNS public support and Web Forwarding
documentation. The rule is intentionally scoped to an UltraDNS-managed redirect
record. It does not infer destination hosting, account control, or broader DNS
authority unless other evidence such as NS records independently supports that.

## Squarespace Managed Subdomain Fingerprint

The catalog now includes a high-confidence Squarespace `cname_target` rule for
`ext-sq.squarespace.com`, sourced from Squarespace support documentation for
manually adding a subdomain to a Squarespace site. The existing
`ext-cust.squarespace.com` rule remains the third-party custom-domain path; this
new rule covers the Squarespace-managed subdomain target observed in aggregate
gap triage. It does not infer plan tier or account relationship.

## Microsoft Internal Chain Motif

The motif catalog now includes `tm_to_azurefd_to_msedge`, the complete ordered
Traffic Manager to Azure Front Door to Microsoft Edge CNAME chain described in
the prior v1.8 validation summary. The existing pairwise motifs remain in place;
the triad adds a clearer complete-chain observation when all three markers occur
in order.

## MCP Output Schema Precision

`get_fingerprints`, `get_signals`, `explain_signal`,
`inject_ephemeral_fingerprint`, `list_ephemeral_fingerprints`,
`clear_ephemeral_fingerprints`,
`cluster_verification_tokens`, `get_infrastructure_clusters`, and
`export_graph`, `test_hypothesis`, `simulate_hardening`, and `get_posteriors`
plus `assess_exposure`, `find_hardening_gaps`, and `compare_postures` now return
`TypedDict`-annotated shapes. `discover_fingerprint_candidates` now returns
typed candidate and sample records, `analyze_posture` advertises its list,
profiled, explained, and profiled-explained variants, and `reevaluate_domain`
advertises the full cached lookup record shape as `LookupResult`. FastMCP turns
those annotations into concrete `$defs` or object properties in each tool's
advertised `outputSchema`, so agents can validate these fields without guessing
from examples.

This is intentionally scoped to low-risk MCP surfaces and stable graph
envelopes plus compact agent-facing helpers and the cache-only lookup
re-evaluation path. `chain_lookup` remains narrative text by design.

## DKIM Weak-Area Guidance

`docs/weak-areas.md` now has a dedicated note for custom DKIM selectors and
branded email senders. The note explains that `No DKIM observed` means no match
at the probed selectors, not proof DKIM is absent, and it tells contributors to
add provider-specific stable selector fingerprints rather than broad guesses.

## Unclassified CNAME Weak-Area Guidance

`docs/weak-areas.md` now explains how to read `Unclassified surface` and
`unclassified_cname_chains`: recon reached a public CNAME chain terminus but did
not match a built-in `cname_target` fingerprint. The note points contributors at
`recon discover <domain>`, public vendor references, repeated validation
evidence, and negative tests before turning a terminus into a catalog rule.

## Public Reproduction Smoke Memo

`validation/2026-06-19-paper-reproduction-smoke.md` records an aggregate-only
smoke run of `validation.reproduce_paper_numbers --profile smoke`. It confirms
the public paper-number harness still runs without private corpora, default
network access, paid services, or per-domain output. The memo is intentionally a
harness-health artifact, not a headline calibration result.

## Scorecard Posture

The public Scorecard API result checked after the dependency batch on
2026-06-19 reported score 6.6 for `github.com/blisspixel/recon`.
The repo already scores 10 on dependency updates, security policy, dangerous
workflows, token permissions, SAST, binary artifacts, vulnerabilities,
packaging, fuzzing, Pinned-Dependencies, and license.

After the most recent push, GitHub opened a high Dependabot alert for
GHSA-6v7p-g79w-8964 through the dev-audit path
`pip-audit[filecache] -> cachecontrol -> msgpack`. The local lockfile now pins
the patched `msgpack` 1.2.1 release, and `pip-audit` reports no known
vulnerabilities.

A follow-on moderate alert, GHSA-4xgf-cpjx-pc3j, identified
`pydantic-settings` through the MCP dependency path. The local lockfile and
ClusterFuzzLite runtime requirements export now use `pydantic-settings` 2.14.2.

The only remaining local Pinned-Dependencies warning in that scan was the
ClusterFuzzLite build script's local `pip install .` command. The fuzz build now
uses a committed hash-pinned runtime requirements export and loads the
checked-out source through `PYTHONPATH`, leaving only one pip install command
for Scorecard to inspect without broadening the fuzzer surface. The follow-up
Scorecard API result reports Pinned-Dependencies at 10.
`scripts/check_clusterfuzzlite_requirements.py` now verifies the committed
ClusterFuzzLite requirements file against a fresh frozen runtime export from
`uv.lock`, so future dependency updates cannot leave that Scorecard-sensitive
artifact stale.
The CI validation job now also runs the fast generated-artifact and ratchet
guards from the local mirror: ClusterFuzzLite requirements, schema source map,
surface inventory, CLI surface docs, no-experimental-labels, file-size ratchet,
and PLR ratchet.
`scripts/check_text_hygiene.py` now scans added lines in staged, unstaged, local
ahead-of-origin, or explicit CI commit-range diffs for attribution markers, em
dashes, and pictographic symbols. This keeps the house style rule mechanical
without rewriting historical prose.

A local-only 2026-06-25 bug-hunt pass fixed SPF complexity aggregation for
malformed domains with multiple SPF TXT records: recon now reports the largest
observed include count instead of overwriting the accumulator with the last SPF
record returned by DNS.

The current dependency-currency batch updates the MCP runtime package to 1.28.0
and the Public Suffix List package to 1.0.2.20260615, plus the dev toolchain
entries for Hypothesis, pytest, pytest-asyncio, Ruff, Pyright, pre-commit, and
pip-audit. The newer Pyright check found one typed socket-address boundary in
the HTTP SSRF guard, now fixed by coercing the `getaddrinfo` address slot to
`str` before the shared IP blocker sees it. `pip-audit` reports no known
vulnerabilities, and GitHub Dependabot has no open alerts as of this check.

Local-file work can improve future release posture most directly through the
Signed-Releases path. The release workflow now waits for build-provenance
attestation, exports the signed GitHub attestation bundles as
`recon-tool-<version>.intoto.jsonl`, and attaches that provenance asset to the
GitHub Release. The local Scorecard posture tests now also require every
workflow to default to read-only token permissions and pin every elevated job
scope to an allowlist, and every checkout step disables persisted Git
credentials. Every workflow job now also has an explicit timeout. ClusterFuzzLite
PR fuzzing is now wired with a Python Atheris target around local parser,
cache-deserializer, and serializer boundaries. The remaining low scores require
external or policy choices: branch protection and code-review settings, elapsed
repository age, outside contributors, OpenSSF Best Practices badge enrollment,
and already-published release assets.

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

## Cache Edge Coverage

`tests/test_cache_roundtrip.py` now pins three cache-boundary contracts:

- pasted URLs and `www.` hosts normalize to the apex cache key;
- `cache_clear_all()` deletes only top-level JSON cache entries, leaving nested
  and non-JSON files alone;
- `shared_verification_tokens` remains batch-scope state and does not persist
  through the per-domain disk cache.

## Profile Baseline Coverage

The `high-value-target` profile now declares `Identity` and
`Security & Compliance` as expected categories. Missing categories surface
through the existing vertical-baseline path as medium consistency observations
with the phrase `absence is observable, not a verdict`. Tests confirm that
`okta` suppresses the identity expectation and `crowdstrike` suppresses the
security expectation.

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
