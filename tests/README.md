# Test Ownership Map

Use this map to find the smallest behavior-owned suite after changing source.
It complements the generated local code graph. It does not replace
`uv run python scripts/check.py`, which remains the complete pre-push gate.

## Working Rule

Put a test beside the behavior owner, not beside the bug report, coverage gap,
release, or feature that happened to reveal it. Prefer an existing focused
suite. A new test file needs a responsibility that cannot be stated accurately
by an existing filename.

Run focused tests while iterating:

```bash
uv run pytest tests/test_cache_roundtrip.py tests/test_ct_cache.py -q
```

Then run the complete gate before pushing:

```bash
uv run python scripts/check.py
```

## Source and Test Owners

| Behavior | Defining source | Focused test owners |
|---|---|---|
| CLI registration and shared callbacks | `src/recon_tool/cli/__init__.py`, `src/recon_tool/cli/shared.py` | `test_cli.py`, `test_cli_crash_handler.py`, `test_cli_integration_smoke.py` |
| Lookup CLI | `src/recon_tool/cli/lookup.py` | `test_cli.py`, `test_lookup_compare_cli.py`, `test_cli_explain.py`, `test_cli_output_contracts.py` |
| Batch CLI and scheduling | `src/recon_tool/cli/batch.py` | `test_batch.py`, `test_batch_stdin.py`, `test_batch_streaming.py`, `test_batch_ndjson_schema.py` |
| Doctor and update flows | `src/recon_tool/cli/doctor.py`, `src/recon_tool/updater.py` | `test_doctor.py`, `test_doctor_client.py`, `test_doctor_mcp.py`, `test_updater.py` |
| Cache behavior and path safety | `src/recon_tool/cache.py`, `src/recon_tool/cache_paths.py`, `src/recon_tool/cache_values.py`, `src/recon_tool/ct_cache.py` | `test_cache_roundtrip.py`, `test_cache_forward_compat.py`, `test_cache_cross_version_compatibility.py`, `test_ct_cache.py` |
| Panel and formatter contracts | `src/recon_tool/formatter/` | `test_formatter.py`, `test_panel_render_snapshots.py`, `test_panel_output_sanity.py`, `test_panel_disclosure.py`, `test_source_status.py` |
| MCP server registration and tools | `src/recon_tool/server/` | `test_server.py`, `test_server_resources.py`, `test_mcp_introspection.py`, `test_mcp_graph_tools.py`, `test_mcp_structured_output.py` |
| MCP client install and doctor | `src/recon_tool/mcp_client/` | `test_mcp_install.py`, `test_mcp_doctor.py`, `test_mcp_path_isolation.py` |
| DNS and public source collectors | `src/recon_tool/sources/` | `test_sources/`, `test_dns_subdetectors.py`, `test_dns_replay.py`, `test_cert_providers.py`, `test_ct_pipeline_resilience.py`, `test_google_identity.py`, `test_oidc_enrichment.py` |
| Fingerprint catalog and matching | `src/recon_tool/fingerprints.py`, `src/recon_tool/fingerprint_*.py` | `test_fingerprints.py`, `test_fingerprint_artifact.py`, `test_fingerprint_expansion.py`, `test_ephemeral_fingerprints.py` |
| Signals and posture | `src/recon_tool/signals.py`, `src/recon_tool/posture.py`, `src/recon_tool/profiles.py` | `test_signals.py`, `test_signals_validation.py`, `test_posture.py`, `test_posture_validation.py` |
| Bayesian and fusion logic | `src/recon_tool/bayesian*.py`, `src/recon_tool/fusion.py` | `test_bayesian_unit_math.py`, `test_bayesian_differential.py`, `test_bayesian_network_invariants.py`, `test_bayesian_fusion.py`, `test_fusion_robustness.py` |
| Correlation graph and motifs | `src/recon_tool/clustering.py`, `src/recon_tool/infra_graph.py`, `src/recon_tool/motifs.py` | `test_clustering.py`, `test_infra_graph.py`, `test_motifs.py` |
| Models, schemas, and claim contracts | `src/recon_tool/models.py`, `src/recon_tool/schema_contract.py`, `src/recon_tool/claim_contract.py`, `src/recon_tool/collection_view.py` | `test_models.py`, `test_data_models.py`, `test_json_schema_contract.py`, `test_schema_resource.py`, `test_claim_contract.py`, `test_collection_view.py` |
| Maintainer validation | `validation/`, `src/recon_tool/validation_runner.py` | `test_validation_runner.py`, `tests/validation/` |

Paths in the test column are relative to `tests/`.

## Compatibility-Only Paths

The top-level `cli_*`, `formatter_*`, `server_*`, `mcp_*`, and
`client_doctor.py` modules under `src/recon_tool/` are v2 compatibility shims.
New runtime code, ordinary tests, and fuzz harnesses import their package-local
defining modules. Only the explicit compatibility suite should import old paths
directly. A shim must never import another shim.

## Transitional Catch-All Suites

Do not add cases to these historical files:

- `test_cli_coverage.py`
- `test_cli_coverage_extra.py`
- `test_formatter_coverage.py`
- `test_gws_features.py`
- `test_enhanced_yaml.py`

Their existing cases will move into behavior-owned suites incrementally. Each
move must preserve collected tests, assertions, coverage, and test isolation.

## Static Map Limits

Direct imports in `.agent/codegraph/impact.jsonl` are the strongest generated
test-owner signal. Heuristic candidates are broader fallbacks. Dynamic fixture
registration, monkeypatch targets, parametrization, and Hypothesis-generated
tests are not fully represented by static import counts. Verify the focused
suite in source before treating a generated list as complete.
