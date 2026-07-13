# MCP Server (AI Agent Integration)

recon runs as a local stdio MCP server so MCP-compatible AI tools can call it
directly, with no API keys and no glue code. The default `pip install recon-tool`
includes the MCP server.

Works with Claude Desktop, Cursor, VS Code + Copilot, ChatGPT, or any other
[MCP client](https://modelcontextprotocol.io/).

> [!WARNING]
> `recon mcp` runs with the privileges of the calling user or editor process.
> Treat connected AI agents as untrusted input: prompt injection, tool
> poisoning, and parameter tampering are possible. Start with manual approvals,
> keep `autoApprove` empty by default, and prefer an isolated workspace or
> container for production agent use.

## Setup

1. Install recon:

```bash
pip install recon-tool
```

2. Wire the MCP server into your client. Two ways:

   **a. One-shot install (recommended).** Let recon write the right config block at the right per-OS path:

   ```bash
   recon mcp install --client=claude-desktop
   # supported: claude-desktop, claude-code, cursor, vscode, windsurf, kiro
   recon mcp install --client=cursor --dry-run        # preview without writing
   recon mcp install --client=cursor --scope=workspace  # project-local instead of user-global
   ```

   The command merges the recon stanza into your existing config without touching sibling MCP servers. Existing `autoApprove` lists, custom `env` vars, `disabled` flags, and any other fields you've added to your recon block survive a `--force` rerun; only `command` and `args` are authoritative on the install side. Writes are atomic (sibling tempfile + `os.replace`), so a partial-write failure leaves the original config intact.

   **b. Reviewed manual install.** Generate the exact interpreter-bound block
   for the client, inspect it, and copy that preview only if automated writing
   is unavailable:

   ```bash
   recon mcp install --client=cursor --dry-run
   ```

   The preview includes the client-specific top-level key, including `servers`
   for VS Code and `mcpServers` for other supported clients. Merge that stanza
   without replacing sibling servers. The generated launcher avoids PATH
   ambiguity and strips the workspace from the import path. Do not replace it
   with a bare `recon` command or hand-write `python -m recon_tool.server` in an
   untrusted working directory.

3. Ask your AI tool something like: "Run a recon lookup on
northwindtraders.com and summarize the observed public configuration, naming
anything unresolved."

Example multi-step prompt for deeper analysis:

> "Look up contoso.com with explain=true. Then run assess_exposure and
> find_hardening_gaps. Finally, simulate_hardening with DMARC reject and
> MTA-STS enforce applied, and explain the model-bound public-evidence index
> change without treating it as an overall security verdict."

## Startup warning

`recon mcp` prints a warning banner to `stderr` before the stdio transport
starts so JSON-RPC framing stays clean on `stdout`. The entrypoint warns about
the server's local privilege level and the need for manual approvals:

```text
================================================================================
recon MCP Server vX.Y.Z

WARNING: This server runs with the privileges of the calling user.
Treat connected AI agents as untrusted input.
Start with manual approvals; only enable auto-approval for tools you
deliberately trust.
================================================================================
```

recon intentionally does not add a separate "safe mode" or "full auto" CLI
flag here. Approval policy belongs in the MCP client config, and the safest
default is an empty `autoApprove` list.

### Running `recon mcp` directly in a terminal

If you launch `recon mcp` (or `python -m recon_tool.server`) by hand in a shell, recon detects that stdin is a TTY and prints a "this is not a REPL" panel before exiting. The MCP server is meant to be spawned by an MCP client over stdio JSON-RPC. Running it interactively used to surface a Pydantic JSON-parse traceback the first time you pressed Enter; the panel replaces that.

If you genuinely need to drive the JSON-RPC loop by hand (e.g. piping crafted requests for debugging), set `RECON_MCP_FORCE_STDIO=1` (case-insensitive: `1`, `true`, `yes`, `on` all enable the bypass) before launching.

## Available Tools

Start with `lookup_tenant` for a single-domain summary and provenance,
`analyze_posture` for categorized public observations, and
`compare_postures` or `cluster_verification_tokens` only for an
operator-supplied domain set. Graph export, posterior inspection, hypothesis
testing, simulation, catalog mutation, and fingerprint discovery are specialist
workflows; a first-time user does not need them for a normal lookup.

| Tool | Network calls? | What it does | Parameters |
|------|----------------|-------------|------------|
| `lookup_tenant` | Cache first; may resolve | Full domain intelligence: tenant details, email score, SaaS fingerprints, signals. When `explain=true`, the response includes a JSON-serialisable `explanation_dag`: evidence occurrences link to matching slug and rule nodes, which link to signal, insight, observation, or confidence terminals. `provenance_complete` and `disconnected_terminals` report whether every terminal is evidence-reachable. The flat explanations list remains alongside the graph. | `domain`, `format`: `text` / `json` / `markdown`, `explain`: bool |
| `analyze_posture` | Cache first; may resolve | Neutral posture observations across email, identity, infrastructure. Accepts an optional `profile` argument: one of `fintech`, `healthcare`, `saas-b2b`, `high-value-target`, `public-sector`, `higher-ed`, or a custom name from `~/.recon/profiles/`. | `domain`, `explain`: bool, `profile`: str (optional) |
| `cluster_verification_tokens` | Cache first; may resolve each domain | Report exact TXT site-verification token reuse. Shared administration, copied configuration, managed service, and stale residue remain compatible explanations; reuse does not establish ownership or current use. Optional peer caps report omitted counts for compact agent output. | `domains`: array of domain strings, `peer_limit_per_domain` (0 means raw) |
| `assess_exposure` | Cache first; may resolve | Model-bound public-evidence index (0-100) with email, identity, and infrastructure sections. It summarizes only collected public observables and is not an overall security score (see [correlation.md](correlation.md) for the inference model). | `domain` |
| `find_hardening_gaps` | Cache first; may resolve | Categorized public-configuration opportunities with "Consider" recommendations and explicit absence semantics. It is not an overall assessment (see [correlation.md](correlation.md)). | `domain` |
| `compare_postures` | Cache first; may resolve both domains | Side-by-side comparison of two domains' public configuration evidence, not overall security | `domain_a`, `domain_b` |
| `chain_lookup` | Yes | Recursive domain discovery via CNAME/CT breadcrumbs. Optional result caps report omitted counts for compact agent output while preserving raw JSON as the default. | `domain`, `depth` (1-3), `result_limit` (0 means raw) |
| `discover_fingerprint_candidates` | Yes | Mine a domain for new-fingerprint candidates. Resolves with unclassified-CNAME-chain capture, applies intra-org and already-covered filters, returns a ranked candidate list. Pair with the `/recon-fingerprint-triage` skill to turn candidates into YAML stanzas. | `domain`, `skip_ct`: bool, `keep_intra_org`: bool, `min_count`: int |
| `reload_data` | No | Reload fingerprints, signals, and posture rules from disk | none |
| `get_fingerprints` | No | List all loaded fingerprints with slugs, categories, detection types | `category` (optional filter) |
| `get_signals` | No | List all loaded signals with rules, layers, conditions | `category`, `layer` (optional filters) |
| `explain_signal` | No unless `domain` is provided | Query a signal's trigger conditions and current state for a domain | `signal_name`, `domain` (optional) |
| `test_hypothesis` | Cache first; may resolve | Test a theory against signals and evidence; returns likelihood + evidence | `domain`, `hypothesis` |
| `simulate_hardening` | Cache first; may resolve | What-if: re-compute the model-bound public-evidence index with hypothetical fixes. This is not a prediction of overall security change (see [correlation.md](correlation.md)). | `domain`, `fixes` (array) |
| `inject_ephemeral_fingerprint` | No | Inject a temporary fingerprint for the current session | `name`, `slug`, `category`, `confidence`, `detections` (array) |
| `reevaluate_domain` | No | Re-evaluate cached domain data against current fingerprints (including ephemeral) | `domain` |
| `list_ephemeral_fingerprints` | No | List all currently loaded ephemeral fingerprints | none |
| `clear_ephemeral_fingerprints` | No | Remove all ephemeral fingerprints from the session | none |
| `get_infrastructure_clusters` *(v1.8+)* | Cache first; may resolve | Surfaces the CT co-occurrence community-detection report already computed during lookup: algorithm, modularity score, cluster list. Read-only exposure of computed state. Optional member caps report omitted counts for compact agent output. | `domain`, `member_limit_per_cluster` (0 means raw) |
| `export_graph` *(v1.8+)* | Cache first; may resolve | Companion to `get_infrastructure_clusters`. Returns the underlying graph as nodes + weighted edges + cluster_assignment for downstream Mermaid / GraphViz / CSV rendering. Optional node and edge caps report omitted counts for compact agent output. | `domain`, `node_limit` (0 means raw), `edge_limit` (0 means raw) |
| `get_posteriors` *(v1.9.0; stable v2.0+)* | Cache first; may resolve | Exposes model-relative Bayesian-network posteriors and evidence-responsive uncertainty bands for the nine high-level claim nodes. Top-level `degraded_sources` and `collection_masked_units` preserve the collection failures that were treated as structurally unobserved rather than negative evidence. Read-only exposure of the inference computed during lookup. See [correlation.md](correlation.md) for the inference model and limits. | `domain` |
| `explain_dag` *(v1.9.0; stable v2.0+)* | Cache first; may resolve | Renders the Bayesian evidence DAG for a domain. `output_format` selects between `text` (Rich-rendered tree) and structured output for downstream tools. Pairs with `get_posteriors` for full audit-trail inspection. | `domain`, `output_format`: str (default `text`) |

The lookup and analysis tools are read-only. The ephemeral fingerprint tools
mutate only in-memory session state for the current server process; they do not
write to disk and do not trigger new network calls on their own. Tools marked
with `explain` support structured provenance output. Catalog tools
(`get_fingerprints`, `get_signals`, and MCP resources) do not call the network.
Domain-analysis tools are cache-first and may resolve the domain when no fresh
cache entry exists. The server includes a bounded TTL cache (120s) and
per-domain rate limiting.

### Tool output: structured content and errors

Aligned with the MCP 2025-11-25 specification, the data tools return their
results as navigable `structuredContent` with a generated per-tool
`outputSchema`, so a client can consume and validate fields directly rather than
re-parsing a JSON string. For backward compatibility each result also carries the
same payload as serialized-JSON text content, so a text-only consumer still
works. The structured tools are the catalog, posture, graph, ephemeral, and
inference tools (`get_fingerprints`, `get_signals`, `explain_signal`,
`assess_exposure`, `find_hardening_gaps`, `compare_postures`, `analyze_posture`,
`discover_fingerprint_candidates`, `test_hypothesis`, `simulate_hardening`,
`cluster_verification_tokens`, `get_infrastructure_clusters`, `export_graph`,
`get_posteriors`, and the ephemeral-fingerprint tools).

The graph, chain, and batch-correlation tools preserve raw access by default.
Passing `result_limit`, `peer_limit_per_domain`, `member_limit_per_cluster`,
`node_limit`, or `edge_limit` asks for a compact payload; the response includes
omitted counts, a deterministic `selection_rule`, and a `raw_request` pointer
so an agent can decide whether to request the raw result.

Compatibility with the MCP 2026-07-28 release candidate is tracked in
[mcp-2026-07-28-readiness.md](mcp-2026-07-28-readiness.md). The dated isolated
matrix passes on both stable SDK v1.28.1 and candidate SDK v2.0.0b1 using the
same local stdio server. Production stays on `mcp>=1.28.1,<2` until the final
specification and stable v2 SDK pass recon's doctor, discovery, schema,
resource, ordering, and full CI gates. Under the candidate, recon explicitly
uses conservative `ttlMs=0`, `cacheScope=private` hints for all six cacheable
methods rather than promising freshness it cannot establish.

The no-network catalog list tools started the precise-schema Phase 2:
`get_fingerprints` advertises a `FingerprintSummary` item schema and
`get_signals` advertises `SignalSummary` plus nested `SignalMetadataSummary`.
`explain_signal` now advertises static-definition and domain-evaluation variants
with `SignalTriggerConditions` and `SignalEvidenceSummary`. The simple
ephemeral-fingerprint session tools now advertise
`EphemeralInjectionResult`, `EphemeralFingerprintSummary`, and
`EphemeralClearResult`. The graph data tools now advertise
`VerificationTokenClusterResult`, `InfrastructureClusterEnvelope`, and
`GraphExportEnvelope`. The compact agent-facing posture helpers now advertise
`HypothesisAssessmentResult` and `HardeningSimulationResult`. `get_posteriors`
now advertises `PosteriorBlockResult`, `PosteriorNodeSummary`, and
`UnitCounterfactualSummary`. The exposure report tools now advertise
`ExposureAssessmentResult`, `GapReportResult`, and `PostureComparisonResult`
with nested evidence and posture record definitions.
`discover_fingerprint_candidates` now advertises `FingerprintCandidate` plus
nested `FingerprintCandidateSample`. `analyze_posture` now advertises its
list, profiled, explained, and profiled-explained result variants.
`reevaluate_domain` now advertises the full cache-only lookup record as
`LookupResult`, with nested definitions for evidence, posteriors, certificate
summaries, infrastructure clusters, surface attributions, chain motifs, and
conflicts. The CLI `--json` v2.0 schema is a separate locked contract.

The narrative tools render prose or DOT and intentionally return text:
`lookup_tenant` (its `format` selects `text` / `json` / `markdown`),
`explain_dag` (Rich tree or Graphviz DOT), `chain_lookup`, and `reload_data`.
For `lookup_tenant`, `format="text"` is a compact agent-readable summary and
now includes a `Subdomain surface:` provider-count line when CNAME-chain
attributions exist. `format="json"` is the detailed machine path: it carries the
full `surface_attributions` array, while `reevaluate_domain` exposes the same
cache-only lookup record with a typed `LookupResult` output schema.

Errors are reported the spec-correct way: an invalid argument, an unresolvable or
uncached domain, a rate-limit, or an internal failure comes back as a tool result
flagged `isError: true` (a raised `ToolError`), not as a success-shaped
`{"error": ...}` payload, so the model can recognize the failure and self-correct.

### Read-only vs stateful (autoApprove guidance)

Each tool carries a `readOnlyHint` annotation so a consuming agent can reason
about what is safe to auto-approve. The split is enforced in code and kept in
sync with this section by `tests/test_mcp_tool_annotations.py`.

**Stateful tools** change the server's in-memory state for the session and are
the ones to keep manual (or approve only when you understand the effect):

- `inject_ephemeral_fingerprint`: adds a temporary fingerprint to the running
  session's catalog.
- `clear_ephemeral_fingerprints`: removes all ephemeral fingerprints from the
  session.
- `reload_data`: re-reads the fingerprint, signal, and posture catalogs from
  disk into the running server.
- `reevaluate_domain`: replaces the cached merged result for one domain after
  applying the session's current fingerprint catalog. It makes no network
  request, but later tools observe the refreshed cached result.

Every other tool is **read-only** (`readOnlyHint=true`): it does not mutate
server state. Note that read-only does not mean "no network": the
domain-analysis tools are cache-first and may make passive outbound DNS / CT /
identity-endpoint queries when no fresh cache entry exists (the "Network
calls?" column above says which). Read-only here means recon does not change
its own state, not that the call is fully offline. An operator comfortable with
passive outbound queries can auto-approve the read-only set; the safe default
remains an empty `autoApprove` list until you have decided per tool.

### Reading the model-relative posteriors

`get_posteriors` returns a point `posterior` under the committed manually encoded
network and an 80% evidence-responsive uncertainty band. The band uses the
model mean and hand-set effective display mass to parameterize a Beta shape,
with a mean-centered fallback at boundaries. It is not a Bayesian credible
interval, frequentist confidence interval, or calibrated probability. A
consuming agent must keep both values model-relative and inspect their evidence
path. Report the claim unresolved rather than collapsing it to the point value
when `sparse=true`, the band straddles the model threshold, or `evidence_used`
is empty and no `unit_counterfactuals` entry records `observed="absent"`.
Absence is not disproof: recon
treats a hideable signal that did not fire as *no evidence*, never as evidence
the technology is absent. This is an explicit conservative policy, not a result
derived from MNAR. A low or sparse model score therefore cannot establish real-
world absence. A declarative node can have an empty `evidence_used` list while
its counterfactuals record a successfully observed public absence; report only
that defined public fact, not private-state absence.
Read top-level `degraded_sources` before interpreting a non-fire.
`collection_masked_units` names the Bayesian dependency units removed because
their collector channel was unavailable. Such a unit contributed neither fired
evidence nor declarative absence; it is not an observed negative.
The injected server instructions carry this same guidance for the agent;
`tests/test_posterior_reading_guidance.py` keeps it from regressing.

## Catalog Resources

recon exposes five MCP resources so agents can browse "what can this tool detect?", "what shape is the output?", and "what local surfaces exist?" without spending a tool invocation on introspection:

| URI | Content |
|---|---|
| `recon://fingerprints` | Full SaaS fingerprint catalog (slug, name, category, confidence, match_mode, detection_count, ...) |
| `recon://signals` | Derived intelligence signals with candidate slugs, min_matches, contradicts/requires relationships, and positive-when-absent inversions |
| `recon://profiles` | Built-in posture profile lenses (category boosts, signal boosts, focus categories) |
| `recon://schema` | The JSON-output contract as a JSON Schema (the same document as `docs/recon-schema.json`), so an agent can self-describe the shape of `recon <domain> --json` (plus the batch / delta modes in its `$defs`) without an external fetch. The contract version is in the schema's own `description`. |
| `recon://surface-inventory` | Generated, non-contractual local map of the CLI, MCP tools, MCP resources, JSON schema, agent integration surfaces, and maintainer-loop context packet. It is the same inventory as `docs/surface-inventory.json`. |

The catalog resources return deterministic JSON sourced from the already-loaded YAML catalogs; `recon://schema` returns the bundled schema document; `recon://surface-inventory` returns the bundled generated inventory. No network calls. Changes to custom `~/.recon/fingerprints/` or `~/.recon/signals.yaml` require calling `reload_data` to take effect. The surface inventory is for local discovery and drift checks, not compatibility promises; see [ADR-0007](adr/0007-surface-inventory-discovery-context.md) for the promotion gate.

### Resource Consumption Examples

How a client exposes resources varies; use its resource browser or resource-read
action before spending a domain-analysis tool call when you only need capability
context.

**Choose a posture profile without guessing.**

1. Read `recon://profiles`.
2. Compare the target type the operator provided with each profile's
   `description` and `focus_categories`.
3. Pass `profile` to `analyze_posture` only when the target type clearly
   matches a listed profile. If it does not, omit `profile`.

**Check whether recon has a published fingerprint for a service.**

1. Read `recon://fingerprints`.
2. Filter `fingerprints[]` by `slug`, `name`, `category`, or
   `detection_types`.
3. If no entry matches, say that no published fingerprint was found. Do not
   infer that the service is absent from a target domain.

**Explain a derived signal before or after a lookup.**

1. Read `recon://signals`.
2. Find the signal by `name` or by a slug in `candidates`.
3. Use `min_matches`, `contradicts`, `requires_signals`, and
   `positive_when_absent` to explain what evidence can drive the signal. Keep
   the language hedged because signals are rule-based observations.

**Validate or inspect JSON shape offline.**

1. Read `recon://schema`.
2. Use the top-level schema for `lookup_tenant(format="json")` or
   `recon <domain> --json`.
3. Use `$defs` for batch, summary, and delta shapes. This is a local resource
   read; it does not require fetching docs from the network.

**Discover local surfaces before choosing a command or tool.**

1. Read `recon://surface-inventory` when a client needs a local map of CLI
   commands, MCP tools, MCP resources, JSON-schema fields, or agent guidance
   files.
2. Use `mcp.tools[]` for tool names, parameters, annotations, and advertised
   output schemas.
3. Use `mcp.resources[]` for local resource URIs to read before spending a
   domain-analysis tool call. Treat the inventory fields as generated discovery
   context, not as a stable runtime contract.

## Staleness Timestamps

Every `TenantInfo` result carries two ISO-8601 UTC fields:

- `resolved_at`: when the live resolution produced this result. Always set.
- `cached_at`: when the on-disk cache entry was written. Set only when the result was served from `~/.recon/cache/`.

Agents can compare the two to decide whether to re-resolve. On a fresh lookup, `cached_at` is `null`. On a cache hit, `resolved_at` is preserved from the original resolution so it reflects *when the data was produced*, not just when the cache entry was last written.

## Ephemeral Fingerprints

Ephemeral fingerprints let AI agents inject temporary detection patterns at runtime. They live in memory only, are scoped to the current server session, and are validated through the same regex/ReDoS checks as built-in fingerprints.

To keep long-running MCP sessions available under prompt injection or abusive
tool calls, ephemeral storage is quota-bounded: at most 100 ephemeral
fingerprints, at most 20 detections on a single injected fingerprint, and at
most 500 total ephemeral detections per process. Oversized injections return a
JSON error; use `clear_ephemeral_fingerprints` or restart the server to reset
the session quota.

### Workflow

1. Look up a domain with `lookup_tenant` (caches DNS data).
2. Inject an ephemeral fingerprint with `inject_ephemeral_fingerprint`.
3. Re-evaluate the domain with `reevaluate_domain` (zero network calls, uses cached data).
4. List active ephemeral fingerprints with `list_ephemeral_fingerprints`.
5. Clear all ephemeral fingerprints with `clear_ephemeral_fingerprints` when done.

### Example: Detecting a custom SaaS service

```
Agent: "Inject an ephemeral fingerprint for Fabrikam's internal platform."

→ inject_ephemeral_fingerprint(
    name="Fabrikam Platform",
    slug="fabrikam-platform",
    category="Internal",
    confidence="medium",
    detections=[{"type": "txt", "pattern": "fabrikam-platform-verify="}]
  )

← {"status": "ok", "name": "Fabrikam Platform", "slug": "fabrikam-platform", "detections_accepted": 1}

Agent: "Now re-evaluate contoso.com to see if they use Fabrikam Platform."

→ reevaluate_domain(domain="contoso.com")

← Updated TenantInfo JSON (includes Fabrikam Platform if TXT record matches)
```

### Example: Listing and clearing

```
→ list_ephemeral_fingerprints()
← [{"name": "Fabrikam Platform", "slug": "fabrikam-platform", "category": "Internal", "confidence": "medium", "detection_count": 1}]

→ clear_ephemeral_fingerprints()
← {"status": "ok", "removed": 1}
```

Ephemeral fingerprints are deliberately local-only and session-scoped. They
change matching rules for the current process; they do not tune Bayesian priors
or persist learning. They support cache-only hypothesis checks without writing
to disk or sharing data and disappear when the server exits.

## Where to Put the Config

| Client | Config file location |
|--------|---------------------|
| Claude Code | Use the bundled plugin at [`agents/claude-code/`](../agents/claude-code/); wires up MCP and ships a skill in one install |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally |
| VS Code + Copilot | `.vscode/mcp.json` in your project |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Kiro (workspace) | `.kiro/settings/mcp.json` |
| Kiro (global) | `~/.kiro/settings/mcp.json` |

Per-agent install scaffolds (config snippets + guidance templates) live under [`agents/`](../agents/), one folder per client.

One format note: VS Code's `.vscode/mcp.json` maps server names under a top-level `servers` key, not `mcpServers` (see the [VS Code MCP configuration reference](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration)). `recon mcp install --client=vscode` writes the correct key; use `--dry-run` to preview the client-specific shape.

### PATH gotcha for GUI clients

GUI MCP clients (Claude Desktop, Windsurf, Cursor, VS Code) typically don't inherit your shell's PATH. Run `recon mcp install --client=<name> --force` from the Python environment where recon is installed. The installer always writes that interpreter's absolute path plus a sys.path-stripping launcher, so the client uses the same recon installation without depending on shell PATH. If you edit by hand, prefer the absolute path to the `recon` script (run `which recon` / `where recon` to find it):

```json
{
  "mcpServers": {
    "recon": {
      "command": "/absolute/path/to/recon",
      "args": ["mcp"]
    }
  }
}
```

The shorter `python -m recon_tool.server` form is acceptable only from a trusted working directory. Python imports through cwd before recon can run its server-side guard, which is why the installer uses the `-c` launcher instead.

### Verify your setup

Three complementary checks. The first two validate the server; the third validates that the client was told about it.

- **`recon doctor --mcp`**: *static* diagnostic. Confirms the MCP dependencies are installed, reports the exact SDK version and generation, loads the server module, enumerates tools through the public server API, and verifies `recon` is on your PATH. It also prints a copy-pasteable reference config. Prefer `recon mcp install --client=<name>` for an actual client because the installer safely merges the recon block without replacing sibling servers or client-specific fields.
- **`recon mcp doctor`**: *live* end-to-end check. Spawns the recon MCP server through the running interpreter, opens a real `stdio_client` + `ClientSession`, runs the discovery flow supported by the installed Python MCP SDK, and asserts the anchor tools (`lookup_tenant`, `analyze_posture`, `assess_exposure`, `find_hardening_gaps`, `chain_lookup`) are registered. Stable v1 uses `initialize` plus `tools/list`; candidate v2 uses `server/discover` plus `tools/list` and validates complete-result cache metadata. If the spawned server crashes during discovery, the trailing twelve lines of its stderr are spliced into the failure detail so you see the actual import failure or traceback instead of an opaque `BrokenPipeError`. 30-second handshake timeout.
- **`recon doctor --client=<name>`**: reads the config file the named client actually loads (`claude-code`, `claude-desktop`, `cursor`, `vscode`, `windsurf`, `kiro`) and reports whether its recon server entry is present and well-formed. This is the config-side complement to the two server checks: they confirm the server is healthy, this confirms the client was told where to find it. For Claude Code it also looks under the project-nested `projects[...].mcpServers.recon` shape that `claude mcp add` writes, and notes that a plugin install keeps its config inside the plugin rather than in `~/.claude.json`. Exits non-zero when no stanza is found, so it is usable in a setup script.

The static check (`recon doctor --mcp`) is the right starting point. If it passes but a client still can't talk to the server, run `recon mcp doctor` to confirm the JSON-RPC loop itself is healthy, and `recon doctor --client=<name>` to confirm the client config carries the stanza.

### When doctor passes but the tools don't load

This is a common failure mode, and it usually is not a broken config. A healthy server the client never re-read looks identical to one wired up correctly, right until the tools fail to appear. If the checks above pass but the tools still do not show up:

- **Run `/mcp` in the client.** It lists the connected MCP servers and any startup error. If `recon` is not listed, the config was not picked up or the server crashed on spawn.
- **Look for the right tool-name prefix.** Local stdio tools appear as `mcp__recon__*`, not `mcp__claude_ai_*`. Searching the tool list for the claude.ai naming pattern will not find them, which can read as "the install failed" when it did not.
- **Restart means a full application quit.** Closing a chat window and opening a new one in the same process does not re-spawn MCP servers. Quit the application entirely (Alt+F4 on Windows, Cmd+Q on macOS) and relaunch.
- **Check which path you installed by.** `recon mcp install --client=claude-code` writes a user-scoped stanza into `~/.claude.json`. The Claude Code plugin instead keeps its config inside the plugin, and the plugin has to be *enabled*, not just present. The two paths are independent; `recon doctor --client` reads the former, not the latter.

### Approval semantics differ by install path

The two ways recon's tools get registered default to different approval behavior, which is worth knowing if you install by both:

- **`recon mcp install` (or a hand-edited config).** The stanza carries `"autoApprove": []`, so every tool call waits for manual approval. This is the safe default and is what the manual-install JSON above shows.
- **The Claude Code plugin.** Plugin-bundled MCP servers are auto-approved when the plugin is enabled, and the plugin `.mcp.json` schema has no `autoApprove` field. Most recon MCP tools are read-only, but `inject_ephemeral_fingerprint`, `clear_ephemeral_fingerprints`, and `reload_data` are stateful for the running session. If you have installed both ways you will have two registrations with different approval semantics. Picking one path avoids the ambiguity, and stateful tools should stay manual unless you deliberately trust that session-local effect.
