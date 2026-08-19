# recon Agent Plugins candidate

Schema-pinned portable packaging candidate for recon-tool 2.17.2. It
contains the complete MCP surface and the two existing recon skills in the
fixed [Agent Plugins v1.0.0](https://agent-plugins.org/specification)
locations.

This directory has passed offline validation against the vendored canonical
Agent Plugins v1.0.0 schemas. The specification remains a Working Draft.
Offline validation is not an unqualified compatibility or conformance claim;
promotion remains blocked on the frozen Visual Studio Code, Cursor, and Kiro
[representative-client evaluation](https://github.com/blisspixel/recon/blob/v2.17.2/docs/agent-portability-evaluation-declaration.md).

Prerequisites:

- Python 3.11 or newer;
- `recon-tool` installed so the client can resolve the `recon` executable;
- client-controlled approval for any networked lookup.

Validate from a recon source checkout:

```bash
uv run python scripts/generate_agent_plugin.py --check
uv run python scripts/check_agent_plugin.py
```

Agent Plugins controls packaging only. It does not change MCP wire behavior,
permissions, stable recon JSON, observation capsules, or the separately
deferred Open Knowledge Format v0.2 projection. Native client scaffolds under
`agents/` remain supported and unchanged during evaluation.
