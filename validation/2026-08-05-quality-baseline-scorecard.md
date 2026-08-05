# Product-quality baseline scorecard

Commit `8a0536b34caa`, catalog `sha256:004afd17fe96`, Python 3.14.4.

Network-free, corpus-free, aggregate-safe. Diagnostic artifact, not a gate.

## MCP context cost

What an agent pays before it does any work.

| Measure | Value |
|---|---:|
| Registered tools | 22 |
| Discovery payload | 81,880 bytes |
| Instruction preamble | 9,996 bytes |
| **Session context before first call** | **91,876 bytes** |
| Order-of-magnitude tokens | ~22,969 |

Where the discovery payload goes:

| Component | Bytes | Share |
|---|---:|---:|
| `outputSchema` | 51,358 | 63.9% |
| `description` | 21,867 | 27.2% |
| `inputSchema` | 4,696 | 5.9% |
| `annotations` | 1,945 | 2.4% |
| `name` | 441 | 0.5% |

Output schemas are 63.1% of discovery. Removing them entirely would leave 30,170 bytes, which is an upper bound on headroom rather than a proposal: structured output is part of the contract clients validate against.

Cross-tool definition duplication accounts for only 6,424 bytes across 5 shared definition bodies, so a shared-definition scheme is not the lever either.

Largest and smallest registered tools:

- `reevaluate_domain` at 14,729 bytes
- `clear_ephemeral_fingerprints` at 583 bytes
- top 5 tools carry 47.4% of discovery

## Catalog surface

| Measure | Value |
|---|---:|
| Entries | 860 |
| Detection rules | 1,070 |
| Rules carrying a verification date | 26 (2.4%) |
| Undated rules | 1,044 |

## Measured elsewhere

| Metric | Owner |
|---|---|
| component latency and peak allocation | `scripts/characterize_performance.py` |
| claim lineage and provenance completeness | `scripts/check_default_claim_audit.py` |
| typed catalog coverage from real results | `validation/catalog_baseline.py` |
| claim-family precision, benefit, and safety | `docs/quality-baseline-preregistration.md` |

## Unmeasured

Named rather than omitted, because an absent metric reads as a passing one.

| Metric | Blocked by |
|---|---|
| classified versus unclassified observable surface | private corpus |
| CT marginal signal gain relative to latency cost | network and private corpus |
| end-to-end cold and warm p50/p95 for single, batch, graph, and MCP workflows | network |
| degraded-source rate and partial-result rate | network and private corpus |
| MCP result payload bytes under real lookups | network |
