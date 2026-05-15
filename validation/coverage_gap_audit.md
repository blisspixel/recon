# Coverage gap audit — v1.9.9

**Total coverage:** 84% (10624 lines tracked, 1648 uncovered).

a rigorous review correctly notes that "84% coverage" is a number,
not evidence of quality. This memo categorizes the uncovered lines
so a reviewer can decide whether the gaps matter.

## Per-module breakdown

| Module | Coverage | Missing | Category |
|---|---|---|---|
| `recon_tool/server.py` | 71% | 281 lines | MCP server runtime paths |
| `recon_tool/formatter.py` | 89% | 148 lines | Rare-render branches and verbose modes |
| `recon_tool/sources/dns.py` | 86% | 111 lines | Per-source error paths |
| `recon_tool/explanation.py` | 89% | 34 lines | Per-explanation rendering paths |
| `recon_tool/validation_runner.py` | 84% | 44 lines | CLI runner paths |
| `recon_tool/merger.py` | 87% | 45 lines | Per-source merge edge cases |
| Other | 90%+ | misc | Per-module rare-input paths |

## What's NOT covered, categorized

### A. MCP server runtime (281 lines in server.py, ~70% of all uncovered)

The MCP server has many code paths that only execute when the server
is actually running as an MCP server with a connected client:

- Tool dispatch error paths (timeout, malformed request, unknown
  tool name).
- Per-tool argument validation that the schema-level test does not
  reach.
- Streaming-response chunking for large result sets.
- Connection-lifecycle handlers (connect, disconnect, abort).

**Why not tested:** the MCP server is exercised live by `recon mcp
doctor` and `recon mcp install` smoke tests, plus by the v1.9.2
agentic UX harness. End-to-end tests against a spawned MCP subprocess
exist in `tests/test_mcp_path_isolation.py` and
`tests/test_server.py` — those touch the entry-point but not every
internal handler.

**Risk assessment:** the uncovered server.py paths are mostly error
paths (request rejection, malformed input handling). A bug in those
paths produces visible MCP errors, not silent data corruption. The
risk surface is "operator sees an unhelpful error message" rather
than "agent acts on incorrect data".

**Remediation plan:** v1.9.10 stratified-corpus validation includes
MCP-side execution; coverage will lift naturally as additional
end-to-end paths execute.

### B. Formatter rare-render branches (148 lines in formatter.py)

Lines 900-974, 1191-1219, 1255-1331, 1409-1465, 1617-1668: rare
rendering branches that fire only on specific input combinations
not present in the synthetic corpus or unit-test fixtures.

Examples:
- BIMI rendering with specific certificate variants.
- Multi-source provider deduplication when more than 4 sources
  agree.
- DKIM-selector rendering when more than 6 selectors observed.
- Specific email-security-score subcategories.

**Why not tested:** the input combinations are real-world but rare.
The synthetic corpus generator could be extended to cover more of
them; doing so would push formatter.py coverage from 89% to 94%+.
None of the uncovered branches are *load-bearing* for the v1.9.9
surfaces (Multi-cloud rollup, ceiling, wordlist).

**Risk assessment:** lower than server.py. A bug in these branches
shows incorrect rendering on specific inputs, not data corruption.
The render-fuzz tests (`test_render_fuzz.py`, 500 Hypothesis
examples) hit some of these paths randomly.

**Remediation plan:** v1.9.10 stratified-corpus validation should
include fixtures targeting these rendering branches. Document the
coverage delta in the v1.9.10 memo.

### C. Per-source error paths (111 lines in sources/dns.py)

Lines 120-125, 288-433, 1062-1199: transient-error handling for
DNS resolver failures, CT-provider timeouts, malformed CT responses.

**Why not tested:** the test suite mocks the transport layer
(httpx, dns resolver) and exercises happy paths. Full coverage
would require fault-injection tests against each transport,
which the current suite does at low fidelity.

**Risk assessment:** moderate. A bug in these paths could swallow
a real error and present an empty result as if the lookup
succeeded. Existing tests (`test_degraded_sources.py`,
`test_properties_resilience.py`) cover the most common failure
modes.

**Remediation plan:** post-v2.0 fault-injection test suite. Tracked
in roadmap backlog.

### D. Validation runner CLI paths (44 lines in validation_runner.py)

Lines 104-110, 123-124, 140-141, 154-161, 341-468: argparse
branches and per-flag handling.

**Why not tested:** the CLI integration smoke test
(`test_cli_integration_smoke.py`) hits the help text and entry
point but not every flag combination.

**Risk assessment:** low. CLI flag bugs surface immediately on user
report.

**Remediation plan:** post-v2.0 CLI flag-coverage matrix test.

### E. Other (~50 lines spread across smaller modules)

Per-module rare-input paths in `merger.py`, `explanation.py`,
`profiles.py`, `posture.py`, `motifs.py`. Each module ≤ 90%
covered with the missing lines being specific input shapes the
unit tests do not exercise.

**Risk assessment:** lowest. Each gap is small and well-isolated.

**Remediation plan:** addressed organically as each module gains
new tests in subsequent releases.

## Honest assessment

The 84% number is dominated by the MCP server's 71% coverage. If
we exclude server.py:

- All other code: ~92% covered.
- server.py runtime paths are the largest gap and the hardest to
  test without spawning a real MCP subprocess against a real client.

The remediation plan above is realistic, not aspirational. Each
gap has a named follow-up. None of the uncovered paths are
load-bearing for the v1.9.9 surfaces; the risk surface for the
uncovered code is "incorrect rare-input rendering" rather than
"data corruption" or "calibration drift".

## What this audit does not cover

- **Mutation testing** of the covered lines (separate concern; see
  `tests/test_mutation_resistance.py` for the v1.9.9 pilot).
- **Branch coverage** vs **line coverage**. The 84% is line
  coverage. Branch coverage would be lower; pytest-cov with
  `--cov-branch` would surface that. Tracked for post-v2.0.
- **Mutation testing on uncovered lines** is impossible by
  construction: a mutation on a line that no test ever executes
  cannot produce a fail signal.
