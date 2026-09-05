# Agent-platform integration review

Reviewed: 2026-09-05 UTC. This is primary-source research and a bounded adoption
plan, not a client compatibility result. No client was installed, no model
session was run, and no target was queried for this review. Moving documentation
must be rechecked against a pinned client release before qualification.

## Reuse the portable boundary

The [Agent Plugins format](https://agent-plugins.org/) defines a shared package
for skills and MCP servers, not installation policy, trust or a sandbox. recon
already generates that package in `agents/agent-plugin/`, with two skills,
the current 23-tool stdio server, pinned v1.0.0 schema checks and persistent
`${PLUGIN_DATA}` state. That directory is the package root, not the repository
root. PyPI installs the runtime, not this source-checkout candidate.

| Platform | Documented route | recon disposition |
|---|---|---|
| Hermes | Its [portable adapter](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins#portable-agent-plugins-v1-packages) loads root manifests, skills and stdio MCP with explicit enablement and profile-scoped plugin data. It declares a supported subset. | Qualify the existing package before writing a native connector. No actual Hermes result is claimed. |
| OpenClaw | Its [bundle loader](https://docs.openclaw.ai/plugins/bundles) documents Agent Plugins, skills, stdio and plugin-data expansion. | Qualify the existing package in the actual loader. A compatible-client listing is not a recon test. |
| Pi | The current [project documentation](https://github.com/earendil-works/pi/tree/main/packages/coding-agent) favors CLI tools and skills; native MCP is not built in. [Skill loading](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/skills.md) supports explicit paths and progressive reading. | Start with CLI plus the existing skill, not an additional MCP bridge or TypeScript package. Verify current package names before publishing recipes. |
| DeepSeek Harness | The [official harness](https://www.deepseek.com/harness/en/) is a developer preview with potential breaking changes. Its [tool contracts](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/tools.md) distinguish canonical results from their persisted presentation. | Borrow result-validation and artifact practices. Do not add a model or preview-harness dependency to recon. |
| NemoClaw | Its [managed MCP lifecycle](https://docs.nvidia.com/nemoclaw/user-guide/openclaw/manage-sandboxes/mcp-servers/about-managed-mcp-servers) accepts Streamable HTTP, not stdio processes or bridges. | The current stdio package is not a managed-endpoint recipe. Running it inside OpenClaw's sandbox is a separate, untested route. The remote recon container remains a draft, not a hosted service. |

These qualification opportunities do not replace or expand the frozen
[VS Code/Cursor/Kiro evaluation](agent-portability-evaluation-declaration.md).
Keep its uncompleted behavioral and cost gates visible. Record any new
loader-only exercise separately, with exact versions and no behavioral claims.

## Improvements worth adopting

1. **Validate proposals before writing artifacts.** The optional historical
   `validation/triage_llm.py` helper read an obsolete catalog path and warned on
   incomplete model output before emitting high-confidence YAML. The repair
   loads built-ins only, rejects malformed or non-bijective responses, serializes
   strings safely, and keeps output explicitly pending human review. Regression
   tests use synthetic responses without a model call. A provider reference supplied by a model is not an
   independent verification, and proposed YAML is not ready for publication.
2. **Resume from evidence artifacts.** recon already has review bundles,
   digest-bound capsules and source receipts. A future private maintainer
   receipt should identify schema, artifact digest, completed gates and pending
   actions. Conversation summaries do not make evidence current. Missing or
   changed artifacts invalidate the dependent review; resumption must not
   silently trigger collection. DeepSeek's [persistence contracts](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/persistence.md)
   are a useful recovery design reference, not a guarantee about recon.
3. **Test actual loading before adding adapters.** A model-free Hermes or
   OpenClaw qualification should verify both skills, all expected tools, local
   catalog resources, paths with spaces, read-only package files, persistent
   data after relocation/update, visible launch failures, restart and
   cancellation. Pi should additionally prove full skill loading and correct
   CLI failure/artifact handling outside the checkout. Use synthetic fixtures;
   a successful handshake proves neither collection nor answer quality.
4. **Preserve data-only trust boundaries.** External DNS text, documentation and
   tool responses remain evidence, never permission to install software,
   query additional namespaces or promote rules. Test directive-like retained
   values through the full skill/CLI route as well as MCP. Do not replace exact
   evidence with a sanitized paraphrase in the authoritative artifact.
5. **Measure progressive disclosure before changing the tool catalog.**
   NemoClaw documents host-side [tool search and description](https://docs.nvidia.com/nemoclaw/user-guide/openclaw/configure-agents/progressive-tool-disclosure).
   Qualify discovery of review, provenance, comparison and catalog tools while
   preserving their schemas and errors. Discovery is not execution policy, and
   a smaller initial prompt alone does not prove better outcomes or lower cost.

## Sandbox interpretation

A stdio connection may work while collection is blocked. Operators must account
for DNS resolver traffic, identity endpoints, CT services and the queried
namespace's MTA-STS endpoint. Google CSE and BIMI certificate requests remain
explicit opt-ins. Do not solve policy failures by silently widening egress or
disabling the sandbox. Preserve available observations and report the affected
`degraded_sources`/`partial` state, not a negative conclusion about controls.
NemoClaw's [policy explanation](https://docs.nvidia.com/nemoclaw/user-guide/openclaw/network-policy/explain-network-policy-to-agents)
can supply host context, but it does not replace recon's source-level evidence.

## Deferred deliberately

No new native platform adapter, remote deployment, automatically learned
fingerprint catalog, model-based confidence score or autonomous promotion loop
is justified by this research alone. Artifact receipts and new host
qualification need bounded acceptance plans before implementation. Keep the
existing frozen corpus, independent review, regression budgets and release
gates as the promotion boundary.
