# MCP Server (AI Agent Integration)

recon runs as a local stdio MCP server so MCP-compatible AI tools can call it
directly, with no API keys and no glue code. The default `pip install recon-tool`
includes the MCP server.

Works with Claude Desktop, Cursor, VS Code + Copilot, ChatGPT, Codex, Gemini CLI, or any other
[MCP client](https://modelcontextprotocol.io/).

> [!WARNING]
> `recon mcp` runs with the privileges of the calling user or editor process.
> Treat connected AI agents as untrusted input: prompt injection, tool
> poisoning, and parameter tampering are possible. Start with manual approvals,
> configure permissions through the client's documented controls, and prefer
> an isolated workspace or container for production agent use.

The local stdio server is the default. An entirely optional, operator-owned
remote Streamable HTTP container and Cloud Run reference are documented in the
[cloud deployment plan](optional-cloud-deployment-plan.md). They are for users
who benefit from shared access or bounded scale-out; they are not required for
any local workflow, and the project does not operate a hosted endpoint. The
remote materials are a draft framework intended to be directionally useful.
They have local artifact checks but are not yet provider-validated or
production-ready.

## DNS view isolation

Ordinary `recon <domain>` keeps its existing trusted-operator resolver behavior
unless the operator opts the CLI in with `RECON_DNS_VIEW=caller-safe` (see
[Encrypted DNS](getting-started.md#encrypted-dns)); the same view described
here then applies. There is no prompt, wizard or required lookup flag. MCP binds one
caller-safe DNS policy automatically at startup, because a connected agent can
be less trusted than the host's private DNS view.

The view is chosen in this order, once per server start:

1. Saved `RECON_DNS_*` settings in the MCP server's environment, reused on
   every restart.
2. If the host already explicitly uses Cloudflare's or Google's published public
   resolver addresses, that same service over certificate-verified
   DNS-over-HTTPS.
3. Otherwise, the encrypted default: Cloudflare DNS-over-HTTPS
   (`https://cloudflare-dns.com/dns-query`, bootstrapped from `1.1.1.1` and
   `1.0.0.1`). This works with no setup on home, enterprise, VPN and
   forwarding-stub networks.

recon never treats an enterprise resolver or a local forwarding stub as proof
of public-only answers, and never sends MCP queries to it. Both the DNS
collectors and HTTP hostname resolution use the bound view, including related
enrichment, recursive chains and fresh review bundles. HTTP still refuses
private/mixed destinations and pins accepted numeric socket addresses.
Transport failures follow the existing explicit source-failure contract; they
never fall back to host, corporate or VPN DNS or to another provider.

The default resolver operator sees the names recon queries; see
[Cloudflare's 1.1.1.1 privacy commitments](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/).
To use a different encrypted service, save it once in the MCP server's
environment configuration. For example, Google Public DNS:

```json
{
  "RECON_DNS_VIEW": "caller-safe",
  "RECON_DNS_SERVERS": "8.8.8.8,8.8.4.4",
  "RECON_DNS_TLS_NAME": "dns.google"
}
```

Quad9 uses `9.9.9.9,149.112.112.112` with `dns.quad9.net`. To disable
DNS-dependent MCP tools entirely, save `RECON_DNS_VIEW=none`; the server still
starts and its offline catalogs remain available. Partial or invalid saved
settings also disable DNS collection rather than silently using the default,
and DNS-dependent tools then report the unavailable capability with a link to
this section. recon never fabricates an empty successful lookup.

`RECON_DNS_SERVERS` accepts one to four numeric bootstrap addresses.
`RECON_DNS_TLS_NAME` is the authenticated resolver hostname. Both are required
for a custom view; a custom address never inherits a guessed provider name.
DoH uses HTTPS port 443 and `/dns-query`. Advanced deployments can set
`RECON_DNS_TRANSPORT=tls` for DNS-over-TLS on port 853 instead. An isolated
enterprise service may be configured when its answers are approved for the
caller; encryption alone does not establish that authorization. TLS uses the
patched certifi bundle and validates the configured service name. Bootstrap
uses the configured numeric address and never host DNS. Allow the selected
transport through egress policy; a network that blocks outbound DoH needs a
saved service it permits. When every source fails or times out under the
caller-safe view, the MCP error says that blocked encrypted DNS is one possible
cause and links this section; it never names the resolver. Resolver operators see queried names; review their
privacy policy before saving a different service.

Advanced trusted internal automation may save `RECON_DNS_VIEW=operator` in a
separate server process restricted to callers allowed to see host DNS. This
does not permit private HTTP destinations. Authentication to a shared server
does not itself authorize internal DNS. Tool arguments, posture profiles,
catalog reloads and later environment mutations cannot change a running
process's policy. Restart after changing trusted server configuration; use a
separate cache directory for operator-view automation. Process cache entries,
retained results and persistent lookup/CT-cache admission bind a policy identity/version
so changing authority does not revive earlier privileged data.

Structured lookup provenance includes `resolution_vantage` (`caller-safe` or
`operator`) and opaque `resolution_policy_id`, without resolver endpoints.
Older records can have null provenance. This isolates recon's collection; it
does not confine an agent with independent unrestricted shell or network tools.

Both MCP doctors report the DNS capability for the launch they check. A
disabled or misconfigured view is a `warn` row with a `Next:` link to this
section; offline tools and local resources remain usable. Refused DNS-dependent calls do not
reserve a rate-limit slot, so retries keep the same actionable setup message.
The live doctor reads a bounded capability declaration from the checked
server's discovery instructions, including mode, transport, and an opaque
policy identity. Resolver addresses are not published. This reports startup
authority, not resolver reachability or another client's environment.

See the [security disposition](security-audit-resolutions.md#closed-in-v2220-cname-chain-walking-can-query-and-leak-internal-dns-names),
[Cloudflare DoH documentation](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/)
and [Google DoH documentation](https://developers.google.com/speed/public-dns/docs/doh).

## Setup

1. Install recon:

```bash
pip install recon-tool
```

### CLI install options

Choose one installation form, then use `recon mcp install` to generate the
client-specific server stanza:

| Form | Command | Tradeoff |
|---|---|---|
| pip | `pip install recon-tool` | Direct installation with the lowest repeat-startup overhead. |
| uv tool | `uv tool install recon-tool` | Isolated persistent tool environment. |
| uvx | `uvx --from recon-tool recon mcp` | No persistent recon installation; the first run may download and cache the package. |

For persisted client configuration, prefer the installer-generated,
interpreter-bound launcher over copying the `uvx` command. It binds the client
to the recon installation you just verified, sets `PYTHONSAFEPATH=1`, and drops
the empty and `.` entries that stand for the working directory from `sys.path`
before importing recon, so a `recon_tool` folder in the client's working
directory is not imported. It starts from any working directory, including your
home directory and a filesystem root. It does not remove import-path entries
that the client environment adds itself, such as `PYTHONPATH=.`. If one of those
makes Python import `recon_tool` through the working directory, the server
refuses to start, exits with status 2, and explains why on stderr.

2. Wire the MCP server into your client. Two ways:

   **a. One-shot install (recommended).** Let recon write the right config block at the right per-OS path:

   ```bash
   recon mcp install --client=claude-desktop
   # supported: claude-desktop, claude-code, cursor, vscode, windsurf, kiro, codex, gemini
   recon mcp install --client=cursor --dry-run        # preview configuration
   recon mcp install --client=cursor --scope=workspace  # project-local instead of user-global
   ```

   The command merges the recon stanza into your existing config without
   touching sibling MCP servers. It refuses an existing `recon` value that is
   not an object unless `--force` is explicit. Client-supported custom fields
   survive a `--force` rerun; canonical launcher fields are refreshed, and
   unsupported legacy approval fields are removed for Claude Code and VS Code.
   Codex is the exception described under [Where to Put the Config](#where-to-put-the-config):
   `--force` replaces the recon TOML span instead of preserving keys inside it.
   Writes are atomic (sibling tempfile plus `os.replace`), so a partial-write
   failure leaves the original config intact. Explicit user-selected config
   symlinks retain their topology. Implicit workspace installs reject symlinks
   and reparse points and retain directory authority throughout reads and
   writes. On Windows this uses temporary guard entries in existing workspace
   directories, including during planning; they are deleted when handles close
   and do not change client configuration. Read-only or unsupported filesystems
   can refuse this operation rather than weaken containment.

   **b. Reviewed manual install.** Generate the exact interpreter-bound block
   for the client, inspect it, and copy that preview only if automated writing
   is unavailable:

   ```bash
   recon mcp install --client=cursor --dry-run
   ```

   The preview includes the client-specific top-level key, including `servers`
   for VS Code, `mcpServers` for other JSON clients, and a `[mcp_servers.recon]`
   table for Codex. Merge that stanza without replacing sibling servers. The generated launcher avoids PATH
   ambiguity and drops the working-directory entries Python itself adds to the
   import path, as described above. Do not replace it with a bare `recon`
   command or hand-write `python -m recon_tool.server` in an untrusted working
   directory. To check this launch from the directory your client starts in,
   run `recon mcp doctor --launch-cwd "<client-working-directory>"`.

3. Ask your AI tool something like: "Run a recon lookup on
gamma.invalid and summarize the observed public configuration, naming
anything unresolved."

Example multi-step prompt for deeper analysis:

> "Look up alpha.invalid with format=json and explain=true. Then run assess_exposure and
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
default is to require confirmation through the client's permission system.

### Running `recon mcp` directly in a terminal

If you launch `recon mcp` (or `python -m recon_tool.server`) by hand in a shell, recon detects that stdin is a TTY and prints a "this is not a REPL" panel before exiting. The MCP server is meant to be spawned by an MCP client over stdio JSON-RPC. Running it interactively used to surface a Pydantic JSON-parse traceback the first time you pressed Enter; the panel replaces that.

If you genuinely need to drive the JSON-RPC loop by hand (e.g. piping crafted requests for debugging), set `RECON_MCP_FORCE_STDIO=1` (case-insensitive: `1`, `true`, `yes`, `on` all enable the bypass) before launching.

Importing the server module does not install a shared logging handler. The
actual stdio runtime supplies a temporary stderr handler only when no host
logging configuration exists, then removes it on exit. By default, request
logging is suppressed (runtime level WARNING); set `RECON_MCP_LOG_REQUESTS=1`
to enable verbose request logging, including full URLs and queried domains.
Warning and exception diagnostics can still contain domain inputs, so review
client logs before sharing them. If the loop fails unexpectedly, stderr receives one bounded
control-free line with the exception type instead of raw multiline exception
text.

## Change notifications

`server/discover` leaves `tools.listChanged`, `prompts.listChanged`,
`resources.listChanged` and `resources.subscribe` false on mcp 2.3.0 and
newer. recon does not send those notifications. Tool, prompt and resource
lists are fixed for the life of the process. `reload_data` can change catalog
resource bodies, and every cacheable result uses `ttlMs: 0`, so a client
re-reads `recon://fingerprints`, `recon://signals` and `recon://profiles`
after a reload. `recon mcp doctor` fails if a future SDK default advertises
any of those flags again. mcp 2.0.0 through 2.2.x accept `subscriptions=False`
and still advertise the flags, so the same doctor check warns on those
releases and names the upgrade.

## Progress

`chain_lookup`, a cache-miss `lookup_tenant`, `build_review_bundle`,
`cluster_verification_tokens`, and `compare_postures` send
`notifications/progress` when the client includes a progress token. A request
without a token produces none. Messages are counts and stage names:

- `chain_lookup`: `depth N: completed of known`. `N` is the same integer as
  `chain_depth`, and the seed is depth 0.
- `cluster_verification_tokens` and `compare_postures`: `domain I of N`,
  before each namespace is resolved, including a cache hit.
- `lookup_tenant` and `build_review_bundle`: one line per collector stage,
  such as `dns: started` or `certificate transparency: done`. A cache hit does
  not collect, so `lookup_tenant` stays silent on that path. `build_review_bundle`
  always resolves fresh.

The text never includes a domain name or a resolver address. The first update
is immediate. Later updates closer than 500 ms are dropped, not delayed, so
nothing is sent after the tool returns. Progress values that are sent increase.
A dropped update can make the next value skip ahead.

A progress notification does not keep a client alive across one collector that
runs longer than the client tool timeout. Codex defaults `tool_timeout_sec` to
60. For `chain_lookup` at depth 2 or 3, enable reset-on-progress or raise that
timeout. This server does not use the Tasks extension.

## Display metadata

Clients that have a title field show that text and fall back to `name` when
the title is absent. `name` values stay the stable contract.

On mcp 2.0.0 and newer, `server/discover` and the initialize `serverInfo`
carry `title` `recon`, the one-line package description, and `websiteUrl`
`https://github.com/pueo-labs/recon`. recon publishes no icon. The v1.28.1
rollback pin forwards `websiteUrl` and the tool, resource, and prompt titles.
Its constructor has no server title or description parameter, so initialize
on that pin omits those two fields.

Catalog resources and the `domain_report` prompt:

| Name | Title |
|------|-------|
| `recon://fingerprints` | List fingerprint catalog |
| `recon://signals` | List signal catalog |
| `recon://profiles` | List posture profiles |
| `recon://schema` | Read output schema |
| `recon://review-bundle-schema` | Read review bundle schema |
| `recon://surface-inventory` | Read surface inventory |
| `domain_report` | Prepare domain briefing |

## Available Tools

Start with `lookup_tenant` for a single-domain summary. Use
`build_review_bundle` when one fresh, evidence-linked handoff should contain
the explained baseline and its review candidates. Use `format="json"` with
`explain=true` on `lookup_tenant` when provenance fields are required. Use
`analyze_posture` for categorized public observations, and
`compare_postures` or `cluster_verification_tokens` only for an
operator-supplied domain set. Graph export, posterior inspection, hypothesis
testing, simulation, catalog mutation, and fingerprint discovery are specialist
workflows; a first-time user does not need them for a normal lookup.

The `domain_report` MCP prompt applies the same domain validator as the tools
before placing a canonical apex in prompt text. Malformed prompt arguments fail
instead of being reflected into an instruction template.

| Tool | Title | Network calls? | What it does | Parameters |
|------|-------|----------------|-------------|------------|
| `lookup_tenant` | Look up domain | Cache first; may resolve | Compact agent-readable summary by default; `format="json"` returns the detailed record as serialized JSON text. Collection uses public DNS and unauthenticated endpoints: authoritative DNS may observe resolver traffic, MTA-STS is the only default target-owned HTTP request, and Google CSE / BIMI certificate probes require explicit opt-in. When `format="json"` and `explain=true`, the serialized record includes an `explanation_dag`: evidence occurrences link to matching slug and rule nodes, which link to signal, insight, observation, or confidence terminals. Schema-version-1 `provenance_complete` and `disconnected_terminals` report graph reachability. `exact_provenance_complete` and `lineage_disconnected_terminals` report whether every terminal has an explicit generation-time evidence-to-rule path. Flat records and terminal nodes carry `lineage_status` (`exact`, `exact_rule_only`, `reconstructed`, or `unsupported`); exact and exact-rule-only records carry one emitter ID in `lineage_rule_ids`. | `domain`, `format`: `text` / `json` / `markdown`, `explain`: bool |
| `build_review_bundle` | Build review bundle | One fresh resolution | Build a NamespaceReviewBundle from exactly one cache-bypassed ordinary passive resolution. Direct probes remain off. The explained lookup, source opportunities, evidence ledger, and review candidates derive from that same result. The artifact is not a security verdict, ownership conclusion, or proof of active product use. | `domain`, `no_ct`: bool, `timeout_seconds`: float |
| `analyze_posture` | Analyze posture | Cache first; may resolve | Neutral posture observations across email, identity, infrastructure. Accepts an optional `profile` argument: one of `fintech`, `healthcare`, `saas-b2b`, `high-value-target`, `public-sector`, `higher-ed`, or a custom name from `profiles/` inside recon's resolved config directory (an absolute `RECON_CONFIG_DIR`, else an existing legacy `~/.recon/`, else `$XDG_CONFIG_HOME/recon`; `recon doctor` prints the resolved path). | `domain`, `explain`: bool, `profile`: str (optional) |
| `cluster_verification_tokens` | Cluster verification tokens | Cache first; may resolve each domain | Report exact TXT site-verification token reuse. Shared administration, copied configuration, managed service, and stale residue remain compatible explanations; reuse does not establish ownership or current use. Optional peer caps report omitted counts for compact agent output. | `domains`: array of domain strings, `peer_limit_per_domain` (0 means raw) |
| `assess_exposure` | Assess exposure | Cache first; may resolve | Model-bound public-evidence index on a 0-100 compatibility scale, with an exact-evidence floor, bounded ceiling, complete weighted component ledger, and email, identity, and infrastructure sections. The current component model assigns at most 90 points. It summarizes only collected public observables and is not an overall security score (see [correlation.md](correlation.md) for the inference model). | `domain` |
| `find_hardening_gaps` | Find hardening gaps | Cache first; may resolve | Categorized public-configuration review prompts with exact generator IDs, basis states, typed predicates, bounded scopes, retained evidence, and "Consider" guidance. It is not an overall assessment (see [correlation.md](correlation.md)). | `domain` |
| `compare_postures` | Compare postures | Cache first; may resolve both domains | Side-by-side comparison of two domains' public configuration evidence, including each namespace's exact exposure-index ledger. Floors and ceilings are not an overall security ranking. | `domain_a`, `domain_b` |
| `chain_lookup` | Follow related domains | Yes | Recursively follows every `related_domains` observation from each ordinary lookup, currently including CT, CNAME, Exchange/identity endpoint, autodiscover, and DKIM tenant-domain breadcrumbs. Each queued name can trigger another full public-metadata lookup. Co-occurrence does not establish ownership or a corporate relationship. Optional result caps report omitted counts for compact agent output while preserving raw JSON as the default. | `domain`, `depth` (1-3), `result_limit` (0 means raw) |
| `discover_fingerprint_candidates` | Discover fingerprint candidates | Cache first; may resolve | Mine unclassified CNAME suffixes for candidates that require independent triage. Surviving heuristics do not establish a third-party service, ownership, current use, or a reusable provider pattern. Pair with the `/recon-fingerprint-triage` skill and require independent documentation or repeated validation evidence before proposing YAML. | `domain`, `skip_ct`: bool, `keep_intra_org`: bool, `min_count`: int |
| `reload_data` | Reload catalogs | No | Reload fingerprint, signal, and posture definitions, clear the process lookup cache, and preserve the rate limiter plus ephemeral catalog | none |
| `get_fingerprints` | List fingerprints | No | List loaded fingerprint definitions with slugs, categories, and detection types. Use `limit` and `offset` for bounded pages. Definitions are capabilities, not target evidence. | `category` (str, optional filter), `limit` (int, optional page size), `offset` (int, default 0; used with `limit`) |
| `get_signals` | List signals | No | List loaded signal definitions with rules, layers, and conditions. Definitions are capabilities, not target evidence. | `category`, `layer` (optional filters) |
| `explain_signal` | Explain signal | No unless `domain` is provided | Query a signal's trigger conditions and current state for a domain | `signal_name`, `domain` (optional) |
| `test_hypothesis` | Test hypothesis | Cache first; may resolve | List observations related to a theory while semantic likelihood remains explicitly unresolved. | `domain`, `hypothesis` |
| `simulate_hardening` | Simulate hardening | Cache first; may resolve | What-if: re-compute the model-bound public-evidence index with hypothetical fixes. Current and simulated ledgers are returned separately, and changed components are labeled `hypothetical_value`. This is not a prediction of overall security change (see [correlation.md](correlation.md)). | `domain`, `fixes` (array) |
| `inject_ephemeral_fingerprint` | Inject ephemeral fingerprint | No | Inject a temporary fingerprint into the current server process; it is process-wide, not conversation-scoped | `name`, `slug`, `category`, `confidence`, `detections` (array) |
| `reevaluate_domain` | Reevaluate cached domain | No | Replace one result in the process lookup cache after replaying retained apex/root TXT, SPF, MX, NS, and CNAME observations against current fingerprints. Owner-qualified detection types require a fresh lookup. | `domain` |
| `list_ephemeral_fingerprints` | List ephemeral fingerprints | No | List all ephemeral fingerprints in the current server process | none |
| `clear_ephemeral_fingerprints` | Clear ephemeral fingerprints | No | Remove all ephemeral fingerprints from the current server process | none |
| `get_infrastructure_clusters` *(v1.8+)* | List infrastructure clusters | Cache first; may resolve | Surfaces the CT co-occurrence community-detection report already computed during lookup: algorithm, modularity score, cluster list. Read-only exposure of computed state. Optional member caps report omitted counts for compact agent output. | `domain`, `member_limit_per_cluster` (0 means raw) |
| `export_graph` *(v1.8+)* | Export infrastructure graph | Cache first; may resolve | Companion to `get_infrastructure_clusters`. Returns the underlying graph as nodes + weighted edges + cluster_assignment for downstream Mermaid / GraphViz / CSV rendering. Optional node and edge caps report omitted counts for compact agent output. | `domain`, `node_limit` (0 means raw), `edge_limit` (0 means raw) |
| `get_posteriors` *(v1.9.0; stable v2.0+)* | Read posteriors | Cache first; may resolve | Exposes model-relative Bayesian-network posteriors and evidence-responsive uncertainty bands for the nine high-level claim nodes. Top-level `degraded_sources` and `collection_masked_units` preserve the collection failures that were treated as structurally unobserved rather than negative evidence. Read-only exposure of the inference computed during lookup. See [correlation.md](correlation.md) for the inference model and limits. | `domain` |
| `explain_dag` *(v1.9.0; stable v2.0+)* | Explain inference graph | Cache first; may resolve | Renders the Bayesian evidence DAG for a domain as plain text or Graphviz DOT text. Pairs with `get_posteriors` for full audit-trail inspection. | `domain`, `output_format`: `text` / `dot` (default `text`) |

For `assess_exposure`, read `observability.components` before interpreting the
compatibility `posture_score`. Each of the nine weighted components carries a
stable generator ID, `state`, typed metadata predicates, observation scope,
awarded and unresolved points, and exact retained evidence. An
`observed_value` may contribute points; `observed_empty` records a completed
bounded opportunity; `unresolved` covers evidence that cannot establish the
modeled state or absence; `unavailable` names a failed collection opportunity;
and `hypothetical_value` appears only in simulation output. These five state
values keep their existing meanings. An optional `applicability` proof block
with `state: not_applicable` retains the published declaration that excludes a
control from this namespace's applicable allocation. The control's original
observation state and evidence remain visible separately. Its awarded and
unresolved points are zero; its nominal component weight stays visible, while
`model_maximum_points` excludes that weight. The index floor is
the sum of awarded points. The ceiling adds unresolved and unavailable modeled
capacity. Neither value is an overall security grade.

A sole valid Null MX declaration excludes MTA-STS, TLS-RPT, and the email
gateway component. DKIM and BIMI also become inapplicable only when the same
available evidence includes an explicit `v=spf1 -all` policy and raw-bound,
effectively enforcing DMARC. A strict SPF policy with permitted senders does
not meet that condition. Mixed MX sets, failed sources, and ambiguous policies
do not establish these exclusions. These are declarations, not delivery tests
or proof about actual mail use. Simulations retain the original applicability
basis, skip inapplicable fixes, and report no awarded points for them.

For `find_hardening_gaps`, read `observation_state` before the prose.
`observed_weak_configuration` and `observed_configuration_inconsistency` carry
retained public-record evidence. `bounded_non_observation` identifies a
successfully collected named scope. `unresolved_hideable_state` means the
control may exist outside that scope, such as DKIM at an operator-chosen
selector. `generator_rule_id`, `metadata_dependencies`, `observation_scope`,
and `evidence` make the basis replayable. `absence_confirmable` remains for
compatibility and must not override the explicit state.
DMARC prompts require the retained record to agree with the derived policy
state. Invalid or ambiguous retained material produces an evidence-backed
review prompt with a distinct basis rather than a record-absence claim. A
missing MTA-STS TXT declaration names only the DNS scope; the HTTP scope appears
only after a valid declaration activated a completed policy request. Simulated
fixes replace the affected proof rows with explicit hypothetical records before
remaining prompts are evaluated.

Exactly four explicit configuration or cache-rewrite tools mutate
caller-visible state in the current server process:
`inject_ephemeral_fingerprint`, `clear_ephemeral_fingerprints`, `reload_data`,
and `reevaluate_domain`. They do not write to disk or trigger new network calls
on their own. All other lookup and analysis tools are read-only, although a
cache miss may perform the documented public-metadata collection. For
`lookup_tenant`, structured provenance requires `format="json"` with
`explain=true`; `analyze_posture(explain=true)` returns flat observation
explanations rather than an `explanation_dag`. Catalog tools (`get_fingerprints`,
`get_signals`, and MCP resources) do not call the network. Definitions describe
matching and derivation capabilities, not target evidence.
Domain-analysis tools are cache-first and may resolve the domain when no fresh
cache entry exists, except `build_review_bundle`, which deliberately bypasses
the result cache and records that choice. The server includes a bounded TTL
cache (120s) and per-domain rate limiting.

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
`get_posteriors`, `build_review_bundle`, and the ephemeral-fingerprint tools).

The graph, chain, and batch-correlation tools preserve raw access by default.
Passing `result_limit`, `peer_limit_per_domain`, `member_limit_per_cluster`,
`node_limit`, or `edge_limit` asks for a compact payload; the response includes
omitted counts, a deterministic `selection_rule`, and a `raw_request` pointer
so an agent can decide whether to request the raw result.

Compatibility with the final MCP 2026-07-28 release is tracked in
[mcp-2026-07-28-readiness.md](mcp-2026-07-28-readiness.md). The dated isolated
matrix passes on both stable SDK v1.28.1 and stable SDK v2.0.0 using the same
local stdio server. Production adopted `mcp>=2.0.0,<3` on 2026-07-31;
v1.28.1 remains the blocking rollback pin. Stable v2 passes recon's doctor,
discovery, schema, resource, ordering, and compatibility gates. Under v2, recon explicitly
uses conservative `ttlMs=0`, `cacheScope=private` hints for all six cacheable
methods rather than promising freshness it cannot establish.

The no-network catalog list tools started the precise-schema Phase 2:
`get_fingerprints` advertises a `FingerprintSummary` item schema and
`get_signals` advertises `SignalSummary` plus nested `SignalMetadataSummary`.
`explain_signal` now advertises static-definition and domain-evaluation variants
with `SignalTriggerConditions` and `SignalEvidenceSummary`. The simple
ephemeral-fingerprint process tools now advertise
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
attributions exist. As of v2.16 it is the same default briefing the panel and
`--plain` render (ADR-0017): it leads with the vendor roles (`Mail:` /
`Identity:` on a role split, `Provider:` otherwise), and cuts insights and
related domains to the high-signal selection with a note pointing at
`format="json"` for the whole record, rather than joining every entry.
`format="json"` is the detailed machine path: it carries the full
`surface_attributions` array and, as of v2.16, the same populated
`fusion_enabled`, `slug_confidences`, and `posterior_observations` the CLI
`--json` default carries (previously the JSON payload advertised these fields
but left them empty). `reevaluate_domain` exposes the same cache-only lookup
record with a typed `LookupResult` output schema.

Error signaling follows the tool's stable return family. Typed data tools raise
`ToolError` for request-level validation and lookup failures, which the MCP
transport reports with `isError: true`; multi-domain tools may instead include
typed per-domain errors inside an otherwise successful aggregate result.
Narrative tools preserve text results for handled failures where documented:
`lookup_tenant` and `explain_dag` return validation, rate-limit, no-data, and
internal-error text; only a resolver `no_data` error is rendered as
`No information found for ...`. Timeouts and total source failure retain
truthful failure text. `chain_lookup` does the same except that a negative
`result_limit` raises `ToolError`; unexpected `reload_data` exceptions propagate
as protocol tool errors. Consumers must handle both ordinary narrative failure
text and `isError: true` results without treating every handled failure as
absence.

### Read-only vs stateful annotations

Each tool carries explicit `readOnlyHint`, `destructiveHint`, `idempotentHint`,
and `openWorldHint` annotations so a consuming agent can reason about what is
safe to auto-approve. The complete 23-tool matrix is enforced in code and kept
in sync with this section by `tests/test_mcp_tool_annotations.py`.

**Explicit state-mutation tools** change caller-visible, process-wide in-memory
state and are the ones to keep manual (or approve only when you understand the
effect):

- `inject_ephemeral_fingerprint`: adds a temporary fingerprint to the running
  process catalog.
- `clear_ephemeral_fingerprints`: removes all ephemeral fingerprints from the
  process catalog and removes their projections from cached results.
- `reload_data`: re-reads the fingerprint, signal, and posture catalogs from
  disk into the running server and clears the process lookup cache. It
  preserves the rate limiter and current ephemeral catalog.
- `reevaluate_domain`: replaces the cached merged result for one domain after
  applying the process's current fingerprint catalog. It makes no network
  request, but later tools observe the refreshed cached result.

`clear_ephemeral_fingerprints`, `reload_data`, and `reevaluate_domain` advertise
`destructiveHint=true` because they remove or replace current process state;
`inject_ephemeral_fingerprint` is additive and advertises
`destructiveHint=false`. All four advertise `openWorldHint=false` because none
interacts with an external entity.

Every other tool is **read-only** (`readOnlyHint=true`): it has no externally
visible side effect beyond returning observations. The server can still update
internal cache, rate-limit, and diagnostic bookkeeping. Read-only also does not
mean "no network": the
domain-analysis tools are cache-first and may make public-metadata DNS, CT,
identity-endpoint, and MTA-STS requests when no fresh cache entry exists (the
"Network calls?" column above says which). DNS can be visible to authoritative
infrastructure, MTA-STS is the one default target-owned HTTP request, and CSE or
BIMI certificate probes require explicit opt-in. Treat annotations as hints and
keep client permission policy explicit after reviewing each tool's network
boundary.

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

recon exposes six MCP resources so agents can browse "what can this tool detect?", "what shape is the output?", and "what local surfaces exist?" without spending a tool invocation on introspection:

| URI | Content |
|---|---|
| `recon://fingerprints` | Full SaaS fingerprint catalog (slug, name, category, confidence, match_mode, detection_count, ...) |
| `recon://signals` | Derived intelligence signals with candidate slugs, min_matches, contradicts/requires relationships, and positive-when-absent inversions |
| `recon://profiles` | Built-in posture profile lenses (category boosts, signal boosts, focus categories) |
| `recon://schema` | The JSON-output contract as a JSON Schema (the same document as `docs/recon-schema.json`), so an agent can self-describe the shape of `recon <domain> --json` (plus the batch / delta modes in its `$defs`) without an external fetch. The contract version is in the schema's own `description`. |
| `recon://review-bundle-schema` | The separate Draft 2020-12 NamespaceReviewBundle v1 contract, byte-identical to `docs/review-bundle-schema.json`, for offline validation of `build_review_bundle` results. |
| `recon://surface-inventory` | Generated, non-contractual local map of the CLI, MCP tools, MCP resources, JSON schema, agent integration surfaces, and maintainer-loop context packet. It is the same inventory as `docs/surface-inventory.json`. |

The catalog resources return deterministic JSON sourced from the already-loaded YAML catalogs; definitions describe matching and derivation capabilities, not evidence about any target. `recon://schema` and `recon://review-bundle-schema` return their bundled contract documents; `recon://surface-inventory` returns the bundled generated inventory. No network calls. Changes to the custom `fingerprints.yaml`, `fingerprints/`, or `signals.yaml` overlay in recon's resolved config directory (an absolute `RECON_CONFIG_DIR`, else an existing legacy `~/.recon/`, else `$XDG_CONFIG_HOME/recon`; `recon doctor` prints the resolved path, and [fingerprints.md](fingerprints.md#custom-fingerprints) has the full rule) require calling `reload_data` to take effect. The surface inventory is for local discovery and drift checks, not compatibility promises; see [ADR-0007](adr/0007-surface-inventory-discovery-context.md) for the promotion gate.

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

1. For quick browsing, start with `get_fingerprints(limit=20, offset=0)`. Add a
   `category` filter when the relevant category is known.
2. A first page cannot establish that the catalog has no match. For an
   exhaustive check, either read the full `recon://fingerprints` resource or
   continue with offsets 20, 40, and so on until a page has fewer than 20
   entries. Omit `category` unless the requested absence is category-scoped.
3. Filter entries by `slug`, `name`, `category`, or `detection_types`.
4. Only after the exhaustive check may you say that no published fingerprint
   was found. Do not infer that the service is absent from a target domain.

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

The internal `TenantInfo` and cache serializer retain two ISO-8601 UTC fields:

- `resolved_at`: when the live resolution produced this result; a manually constructed object may omit it.
- `cached_at`: when the on-disk cache entry was written. Set only when the result was served from `cache/` inside recon's resolved cache directory (an absolute `RECON_CONFIG_DIR`, else an existing legacy `~/.recon/`, else `$XDG_CACHE_HOME/recon`).

These fields are deliberately absent from the public v2 lookup JSON, including
`lookup_tenant(format="json")`. Agents cannot inspect them through that output.
An ordinary lookup can reuse the default 24-hour result cache, so receipt time
does not establish collection time. For a requested fresh handoff, use
`build_review_bundle(domain)`; the CLI equivalent for an ordinary fresh lookup
is `recon "<validated-domain>" --no-cache`. Neither route guarantees that every
upstream record is current: retain source status, partial-collection, and CT
cache notes. These are fresh collection attempts, not per-record freshness
attestations.

For internal callers, `cached_at` is `null` on a fresh lookup. A cache hit
preserves the original `resolved_at` and stamps `cached_at` from the persisted
cache-write time. This internal metadata is not an additional public contract.

## Ephemeral Fingerprints

Ephemeral fingerprints let AI agents inject temporary detection patterns at runtime. They live in memory only, are process-wide within the current server process rather than conversation-scoped, and are validated through the same regex/ReDoS checks as built-in fingerprints.

To keep long-running MCP server processes available under prompt injection or abusive
tool calls, ephemeral storage is quota-bounded: at most 100 ephemeral
fingerprints, at most 20 detections on a single injected fingerprint, and at
most 500 total ephemeral detections per process. Oversized injections return a
MCP tool error (`isError: true`); use `clear_ephemeral_fingerprints` or restart
the server to reset the process quota.

### Workflow

1. Look up a domain with `lookup_tenant` (caches DNS data).
2. Inject an ephemeral fingerprint with `inject_ephemeral_fingerprint`.
3. Re-evaluate the domain with `reevaluate_domain` (zero network calls, uses cached data).
4. List active ephemeral fingerprints with `list_ephemeral_fingerprints`.
5. Clear all ephemeral fingerprints with `clear_ephemeral_fingerprints` when done.

Cached re-evaluation is intentionally narrower than fresh collection. It can
replay `txt`, `spf`, `mx`, `ns`, and apex/root `cname` rules from retained DNS
observations. It cannot replay owner-qualified `cname_target`, `subdomain_txt`,
`caa`, `srv`, or `dmarc_rua` rules; `reevaluate_domain` returns a tool error when
any active ephemeral fingerprint uses one of those types. To test such a rule,
call `reload_data` to clear the process lookup cache while retaining
the ephemeral catalog, then run `lookup_tenant` again. That fresh lookup uses
the normal documented network boundary and is not a zero-network operation.

### Example: Detecting a custom SaaS service

```
Agent: "Inject an ephemeral fingerprint for Synthetic Beta's internal platform."

→ inject_ephemeral_fingerprint(
    name="Synthetic Beta Platform",
    slug="beta-platform",
    category="Internal",
    confidence="medium",
    detections=[{"type": "txt", "pattern": "beta-platform-verify="}]
  )

← {"status": "ok", "name": "Synthetic Beta Platform", "slug": "beta-platform", "detections_accepted": 1}

Agent: "Now re-evaluate alpha.invalid to see if they use Synthetic Beta Platform."

→ reevaluate_domain(domain="alpha.invalid")

← Updated TenantInfo JSON (includes Synthetic Beta Platform if TXT record matches)
```

### Example: Listing and clearing

```
→ list_ephemeral_fingerprints()
← [{"name": "Synthetic Beta Platform", "slug": "beta-platform", "category": "Internal", "confidence": "medium", "detection_count": 1}]

→ clear_ephemeral_fingerprints()
← {"status": "ok", "removed": 1}
```

Ephemeral fingerprints are deliberately local-only and process-scoped. They
change matching rules for the current process; they do not tune Bayesian priors
or persist learning. They support cache-only hypothesis checks without writing
to disk or sharing data and disappear when the server exits.

## Where to Put the Config

| Client | Config file location |
|--------|---------------------|
| Claude Code | Released MCP path: `recon mcp install --client=claude-code`. Marketplace plugin path: `claude plugin marketplace add pueo-labs/recon`, then `claude plugin install recon@pueo-labs-recon`. The plugin still launches `recon` from PATH. |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally |
| VS Code + Copilot | `.vscode/mcp.json` in a workspace, or `mcp.json` in the active user profile |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Kiro (workspace) | `.kiro/settings/mcp.json` |
| Kiro (global) | `~/.kiro/settings/mcp.json` |
| Codex (user) | `~/.codex/config.toml` |
| Codex (trusted project) | `.codex/config.toml` |
| Gemini CLI (user) | `~/.gemini/settings.json` |
| Gemini CLI (project) | `.gemini/settings.json` |

The repository marketplace is [`.claude-plugin/marketplace.json`](../.claude-plugin/marketplace.json).
It installs the existing plugin under [`agents/claude-code/`](../agents/claude-code/),
including its skills. Install `recon-tool` first: the plugin launches `recon`
from PATH. A source checkout can still load that directory for one session with
`claude --plugin-dir ./agents/claude-code`. GUI PATH limits and the doubled
registration from also running `recon mcp install` are covered under
[PATH gotcha for GUI clients](#path-gotcha-for-gui-clients) and
[Client approval policy](#client-approval-policy).

The MCP Registry entry is metadata for clients that install from an index.
`server.json` names `io.github.pueo-labs/recon` and declares
`uvx --from recon-tool recon mcp`. That command runs the `recon` console
script from the `recon-tool` package. A client that inserts the package
identifier between the runtime arguments and the package arguments builds
a different command, so that insertion does not match this entry.
`recon mcp install` remains the interpreter-bound path. The Registry
record points at the PyPI release. It is not a second build, and the
Registry is preview. The organization entry is prepared, not yet published:
the existing v2.27.0 package still identifies `io.github.blisspixel/recon`.
Follow the [repository transfer checklist](release-process.md#repository-transfer-checklist)
for the next authorized release and old-entry deprecation. Existing marketplace
users should follow the [marketplace migration](../agents/claude-code/README.md#marketplace-migration).

Per-agent install scaffolds (config snippets + guidance templates) live under [`agents/`](../agents/), one folder per client.

One format note: VS Code maps server names under a top-level `servers` key, not
`mcpServers`, and its current stdio schema requires `"type": "stdio"` (see the
[VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration),
reviewed 2026-07-13). `recon mcp install --client=vscode` writes the workspace
form by default. VS Code also supports a user-profile file; open it with **MCP:
Open User Configuration** and pass that path with `--config-path` when desired.
VS Code does not define `autoApprove` in this file format.

Codex stores MCP servers in TOML. `recon mcp install --client=codex` writes
`[mcp_servers.recon]` in `~/.codex/config.toml`, or `.codex/config.toml` when
the project is trusted. A matching command and args leave the file unchanged,
including comments and extra keys inside the table. `--force` replaces only
that table's span, so custom keys inside the span do not survive, while sibling
tables and comments outside it do. The install does not write
`tool_timeout_sec` or `default_tools_approval_mode`. `tool_timeout_sec`
defaults to 60 seconds, and `chain_lookup` can take longer. Gemini CLI uses
the JSON merge into `~/.gemini/settings.json` or `.gemini/settings.json` and
omits `autoApprove`, because its server schema rejects that field. Its
per-server timeout is milliseconds, and the documented default is 600000. The
install does not write a timeout. Scaffolds live in
[`agents/codex/`](../agents/codex/) and [`agents/gemini/`](../agents/gemini/).

The installer prints a verification command bound to the file it wrote.
For a profile file, run `recon doctor --client=vscode --config-path "<profile-file>"`.
This inspects only that explicit file; it does not fall back to the workspace
config or start a client. `--config-path` requires `--client` and is not an
option to the separate `recon mcp doctor` live-server diagnostic.

## Troubleshooting

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

The shorter `python -m recon_tool.server` form is acceptable only from a trusted working directory. Python imports through cwd before recon can run its server-side guard, which is why the installer uses the `-c` launcher instead. Approval and trust fields are client-specific; do not copy an `autoApprove` property into a client schema that does not define it.

### Verify your setup

Three complementary checks. Run them in this order. The first two validate the
installed server; the third validates that the named client was told about it.

1. **`recon doctor --mcp`**: static diagnostic. Confirms the MCP dependencies
   are installed, reports the exact SDK version and generation, loads the
   server module, requires server instructions, and enumerates the canonical
   tool and resource registrations through the public server API. It exits
   non-zero if any required registration is absent. It also reports PATH state
   and prints a reference config. Prefer
   `recon mcp install --client=<name>` for an actual client because the
   installer safely merges the recon block without replacing sibling servers
   or client-specific fields. Codex `--force` replaces the recon table span
   and still keeps sibling tables.
2. **`recon mcp doctor`**: live local stdio diagnostic. It runs two labeled
   launches and prints the command, arguments, added environment entries, and
   working directory each one used. The isolated install check starts
   `python -m recon_tool.server` through the running interpreter in a new empty
   temporary directory; it verifies the installation, not a client launch. The
   generated client launch check starts the exact command, arguments, and
   environment entries that `recon mcp install` writes, from the current
   directory or from `--launch-cwd "<dir>"`. Pass the directory your MCP client
   starts in, such as your home directory, to check that launch. A pass covers
   only the directory shown; a client that starts elsewhere, or that passes a
   different environment, can still differ. For each launch the doctor opens a
   real `stdio_client` plus `ClientSession` and runs the discovery flow
   supported by the installed Python MCP SDK. It requires the anchor tools (`lookup_tenant`,
   `analyze_posture`, `assess_exposure`, `find_hardening_gaps`,
   `chain_lookup`), lists all six canonical local resources, and reads each
   one. Every read must return one matching `application/json` text item whose
   payload is a JSON object. Catalog counts, lists, and identifiers must agree;
   fingerprint detection summaries must be populated; and the schema and
   surface inventory must retain their identifying contract structure. These
   resource reads are local and make no target network request. Stable v1 uses
   `initialize`; stable v2 uses
   `server/discover` and validates complete-result cache metadata for discovery,
   listing, and reads. A failure retains completed check rows and names the
   failed protocol phase. Spawned-server stderr is limited to its trailing
   twelve lines, and resource payload text is never copied into failure detail.
   Each launch has a 30-second timeout. This command does not inspect any
   client configuration.
3. **`recon doctor --client=<name>`**: reads the config file the named client
   actually loads (`claude-code`, `claude-desktop`, `cursor`, `vscode`,
   `windsurf`, `kiro`, `codex`, `gemini`) and reports whether its recon server entry is present
   and well-formed. For Claude Code it also looks under the project-nested
   `projects[...].mcpServers.recon` shape that `claude mcp add` writes, and
   notes that a plugin install keeps its config inside the plugin rather than
   in `~/.claude.json`. A missing `args` field, an empty list, or a list
   containing any non-string value is a failing diagnostic. The check exits
   non-zero when no usable stanza is found, so it is suitable for setup
   automation. Add `--config-path "<client-file>"` to check the same explicit
   user-profile or custom file used during installation. Add `--json` for the
   same rows as one JSON object on stdout with the same exit code.

All three print the same status words, `ok`, `warn`, `fail`, and `info`.
MCP warning and failure rows include their `Next:` action when available;
warnings keep exit 0 while distinguishing local protocol success from DNS
collection readiness. A `recon` launcher missing from PATH
is an `info` row in `recon doctor --mcp`, because the generated config falls
back to the running interpreter.

`chain_lookup` advertises an integer `depth` from 1 through 3 and rejects
out-of-range or non-integer values before collection and rate-limit admission.
It does not silently clamp a request to a different depth.

If all three pass but tools still do not appear, continue with the client-side
checks below.

### When doctor passes but the tools don't load

This is a common failure mode, and it usually is not a broken config. A healthy server the client never re-read looks identical to one wired up correctly, right until the tools fail to appear. If the checks above pass but the tools still do not show up:

- **Run `/mcp` in the client.** It lists the connected MCP servers and any startup error. If `recon` is not listed, the config was not picked up or the server crashed on spawn.
- **Look for the right tool-name prefix.** Local stdio tools appear as `mcp__recon__*`, not `mcp__claude_ai_*`. Searching the tool list for the claude.ai naming pattern will not find them, which can read as "the install failed" when it did not.
- **Restart means a full application quit.** Closing a chat window and opening a new one in the same process does not re-spawn MCP servers. Quit the application entirely (Alt+F4 on Windows, Cmd+Q on macOS) and relaunch.
- **Check which path you installed by.** `recon mcp install --client=claude-code` writes a user-scoped stanza into `~/.claude.json` (or `$CLAUDE_CONFIG_DIR/.claude.json` when that environment variable is set for profile isolation or Omarchy account switching). The Claude Code plugin instead keeps its config inside the plugin, and the plugin has to be *enabled*, not just present. The two paths are independent; `recon doctor --client` reads the former, not the latter.

### Client approval policy

Server registration and tool approval are separate. Claude Code plugin servers
start automatically when the plugin is enabled, but their tool calls follow the
same permission system as user-configured servers. The plugin `.mcp.json`,
Claude Code config, and VS Code `mcp.json` do not define a generic
`autoApprove` field. Use the client's documented permission rules when you want
an allowlist, and keep the four process-state tools listed under
[Available Tools](#available-tools) subject to deliberate review. Installing
both the plugin and a user-level server creates two registrations; choose one
path unless that duplication is intentional. See the
[Claude Code MCP reference](https://code.claude.com/docs/en/mcp), reviewed
2026-07-13.
