# Progress Log

This file records maintainer-loop work performed in this checkout. It is a local
planning artifact and does not replace `CHANGELOG.md`.

## 2026-06-23 to 2026-06-24

Session: roadmap research, calibration corpus run, two bug-hunt rounds, QoL
refine, docs currency. All commits are local (unpushed) pending maintainer
review. Local gate (`scripts/check.py`) green throughout; external spend 0 USD.

- Mapped `docs/agentic-balance.md` to the 2026 deterministic-control security
  consensus (OWASP / AWS four-principles). Commit 42d384b.
- Added `validation/progress.py` (`gather_with_progress`), a throttled stderr
  heartbeat for the multi-hour resolve sweeps, wired into the reference and
  tenancy calibration harnesses (conformal reuses reference). Counts only; no
  domain crosses the boundary. Unit-tested. Commit eed11c3.
- Added Gotchas sections to the recon and recon-fingerprint-triage skills per the
  Anthropic skill-authoring guidance. Commit d253fe4.
- Ran the full calibration bundle against the private corpus (5,241 domains, 22
  verticals) at concurrency 2, one harness at a time, each checkpointed and
  disclosure-verified. Aggregates committed at
  `validation/2026-06-23-full-corpus-calibration.md`. Commit a9cbfbb. Result:
  email-policy full posterior ECE 0.076 (DMARC-anchored), held-out residual
  disconfirmed (ECE 0.373), M365 tenancy corroboration ECE 0.048 / agreement
  0.889, conformal coverage 0.999 at a 0.90 target. Does not upgrade the 80%
  credible intervals to frequentist coverage.
- Revised the email-policy calibration claim from "tier 4 residual" to the honest
  full-corpus reading across statistical-assurance, roadmap, assurance-case,
  related-work, and the paper drafts. Commit 826a517.
- Bug-hunt round 1: fixed three boundary-unaware substring matches (lexical
  region matcher, CT subdomain sort endswith, insight classifier), each with a
  regression test. Commit 5d19c6f.
- Bug-hunt round 2: fixed the retry transport returning a closed response on the
  sleep-cap path, the `infra_graph` `dominant_issuer` nondeterminism (a
  byte-identical-output violation), and DMARC whitespace-around-equals parsing,
  each with a test. Commit d12b739.
- QoL refine: accept trailing-dot FQDNs in the validator; corrected two stale
  comments (`ct_cache` TTL, `discovery` brand-stem example). Commit 48de23b.
- Reported but not auto-fixed (maintainer decision): `profiles` `signal_boost` is
  inert (signal-name keys vs rendered statements); the cert early-stop heuristic;
  SPF include-count overwrite on dual-SPF records; the `google_identity`
  federated-redirect substring smell.
- Docs currency: CHANGELOG Unreleased populated with the seven user-facing fixes;
  this log and CURRENT-STATE-ANALYSIS updated; README input-forgiving line notes
  trailing-dot.
- 2026-06-24 external best-practices refresh: checked current MCP, OWASP
  agent-skill, OWASP agent-security, GitHub attestation, and SLSA guidance.
  The actionable local gap was not a new runtime feature, but stale MCP
  launch guidance around hand-written `python -m recon_tool.server`.
- Aligned `recon doctor --mcp` with the installer so the copy-paste config uses
  the sys.path-stripping Python fallback when `recon` is off PATH.
- Added `recon doctor --client` warning coverage for unisolated Python module
  launch blocks in client configs.
- Updated MCP and per-agent setup docs to prefer `recon mcp install` or an
  absolute `recon` script path, and fixed the Claude Code skill's schema
  wording and relative link to the stable v2.0 contract.
- Focused validation passed:
  `uv run python -m pytest tests/test_doctor.py tests/test_doctor_client.py tests/test_mcp_path_isolation.py tests/test_surface_inventory.py -q`
  with 53 passed, 2 skipped;
  `uv run python -m ruff check ...` passed; and
  `python scripts/check_text_hygiene.py` passed.
- Full local gate passed with `uv run python scripts/check.py`: 3550 passed, 5
  skipped, 4 deselected, total coverage 86.57 percent. All gate stages passed.
  External spend remained 0 USD.

## 2026-06-19

- Added `scripts/check_text_hygiene.py` to scan added diff lines for
  attribution markers, em dashes, and pictographic symbols without requiring a
  cleanup of historical prose.
- Wired `text-hygiene` into `scripts/check.py` and into the CI validation job
  using the explicit `HEAD^..HEAD` range.
- Added `tests/test_text_hygiene.py` for unified-diff parsing, runtime-built
  forbidden marker detection, and location rendering.
- Focused text-hygiene validation passed:
  `uv run python scripts/check_text_hygiene.py`,
  `uv run python -m pytest tests/test_text_hygiene.py tests/test_scorecard_posture.py tests/test_markdown_links.py -q`,
  `uv run python -m ruff check scripts/check_text_hygiene.py tests/test_text_hygiene.py tests/test_scorecard_posture.py scripts/check.py`,
  and
  `uv run python -m pyright scripts/check_text_hygiene.py tests/test_text_hygiene.py tests/test_scorecard_posture.py scripts/check.py`.
- Fast local gate with `uv run python scripts/check.py --fast`: pass.
- Added `scripts/check_clusterfuzzlite_requirements.py` to compare the committed
  ClusterFuzzLite hash-pinned runtime requirements file with a fresh frozen
  export from `uv.lock`.
- Wired `clusterfuzzlite-requirements` into `scripts/check.py` as a fast core
  stage so future dependency updates cannot leave stale fuzz-build inputs.
- Added focused tests for the export command, autogenerated-header
  normalization, stale dependency detection, and the current committed export.
- Added the same ClusterFuzzLite requirements export check, schema source-map
  check, CLI surface-doc check, and PLR ratchet to the CI validation job so the
  local fast guard family is mirrored remotely.
- Added `tests/test_scorecard_posture.py` coverage pinning the CI validation
  commands.
- Focused CI parity validation passed:
  `uv run python -m pytest tests/test_scorecard_posture.py tests/test_clusterfuzzlite_requirements_check.py tests/test_clusterfuzzlite_integration.py tests/test_workflow_pins.py tests/test_markdown_links.py -q`,
  `uv run python scripts/check_workflow_pins.py`, and
  `uv run python scripts/check_clusterfuzzlite_requirements.py`.
- Fast local gate after the CI workflow update:
  `uv run python scripts/check.py --fast` passed.
- Focused validation passed:
  `uv run python scripts/check_clusterfuzzlite_requirements.py`,
  `uv run python -m pytest tests/test_clusterfuzzlite_requirements_check.py tests/test_clusterfuzzlite_integration.py -q`,
  `uv run python -m ruff check scripts/check_clusterfuzzlite_requirements.py tests/test_clusterfuzzlite_requirements_check.py scripts/check.py`,
  and
  `uv run python -m pyright scripts/check_clusterfuzzlite_requirements.py tests/test_clusterfuzzlite_requirements_check.py scripts/check.py`.
- Fast local gate with `uv run python scripts/check.py --fast`: pass.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.52 percent. Tests: 3511 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Reproduced the failing Dependabot python-dependencies typecheck locally after
  GitHub reported PR #10 as unstable.
- Updated the lockfile for the grouped dependency batch:
  `mcp` 1.27.0 to 1.28.0, `hypothesis` 6.152.1 to 6.155.6,
  `pytest` 9.0.3 to 9.1.1, `pytest-asyncio` 1.3.0 to 1.4.0,
  `ruff` 0.15.11 to 0.15.18, `pyright` 1.1.408 to 1.1.410,
  `pre-commit` 4.5.1 to 4.6.0, and `pip-audit` 2.10.0 to 2.10.1.
- Folded in the clean public suffix dependency PR by updating
  `publicsuffixlist` from 1.0.2.20260611 to 1.0.2.20260615.
- Regenerated `.clusterfuzzlite/requirements.txt` from the frozen lockfile so
  PR fuzzing continues to use hash-pinned runtime requirements.
- Fixed the Pyright 1.1.410 failure in `src/recon_tool/http.py` by converting
  the `getaddrinfo` socket-address host field to `str` before passing it to the
  shared IP blocker.
- Focused validation passed:
  `uv run python -m pyright src/recon_tool tests`,
  `uv run python -m ruff check src/recon_tool/http.py tests/test_http.py tests/test_http_advanced.py`,
  `uv run python -m pytest tests/test_http.py tests/test_http_advanced.py tests/test_clusterfuzzlite_integration.py -q`,
  `python -m pip install --dry-run --require-hashes -r .clusterfuzzlite/requirements.txt`,
  and `uv run pip-audit`.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.49 percent. Tests: 3507 passed, 5 skipped, 4 deselected.
- Pushed commit `776c477` to `main`.
- Remote verification after the push: CI, Scorecard supply-chain security,
  secrets scan, and both dependency graph updates completed successfully.
- `uv run python scripts/release_readiness.py --remote` passed against
  `HEAD`.
- The public Scorecard API reported score 6.6 for the dependency batch, with
  Pinned-Dependencies, Vulnerabilities, and Fuzzing at 10.
- GitHub Dependabot reported no open alerts, and the superseded Dependabot PRs
  were no longer open after the default branch update.
- External spend: 0 USD.
- Closed the moderate Dependabot alert for GHSA-4xgf-cpjx-pc3j after GitHub
  reported it on the default branch.
- Confirmed the affected path is `mcp -> pydantic-settings`.
- Ran `uv lock --upgrade-package pydantic-settings`, updating `uv.lock` from
  `pydantic-settings` 2.14.0 to 2.14.2.
- Regenerated `.clusterfuzzlite/requirements.txt` from the patched lockfile so
  the hash-pinned fuzz build uses the fixed version.
- External spend: 0 USD.
- Queried the public Scorecard API after the supply-chain fix; it reported
  score 6.5 for `github.com/blisspixel/recon` at commit
  `65e1e58681242ddc525b7a99c96e426472fab5d4`.
- Identified the remaining local-file Pinned-Dependencies warning:
  `.clusterfuzzlite/build.sh` installed the local package through `pip install
  .`, which let pip resolve dependencies without hashes.
- Generated `.clusterfuzzlite/requirements.txt` from `uv.lock` with
  `uv export --frozen --no-dev --no-emit-project --format requirements.txt`.
- Updated `.clusterfuzzlite/build.sh` to install those runtime dependencies
  with `--require-hashes`, then load the checked-out source through
  `PYTHONPATH` so the build script has only one pip install command.
- Rechecked the public Scorecard API and confirmed `pip install --no-deps .`
  was still scored as an unpinned pip command, so the local project install was
  removed entirely.
- Added a ClusterFuzzLite integration test that pins the hash-required
  requirements install and source-path loading behavior.
- External spend: 0 USD.
- Closed the high Dependabot alert for GHSA-6v7p-g79w-8964 after GitHub
  reported it on the default branch.
- Confirmed the affected path is dev-audit only:
  `pip-audit[filecache] -> cachecontrol -> msgpack`.
- Ran `uv lock --upgrade-package msgpack`, updating `uv.lock` from
  `msgpack` 1.1.2 to 1.2.1.
- Verified with `uv tree --invert --package msgpack` and
  `uv run pip-audit`, which reported no known vulnerabilities.
- External spend: 0 USD.
- Updated the stale JSON-contract count in `docs/stability.md`.
- Added `tests/test_stability_docs.py`, which reads `docs/recon-schema.json`
  and the live MCP tool registry, then verifies the stability summary advertises
  the current top-level property count, required-field count, and MCP tool
  count.
- Updated changelog and local loop skills to record the docs-count guard.
- Focused validation:
  `uv run python -m pytest tests/test_stability_docs.py tests/test_markdown_links.py -q`
  passed with 3 tests.
- MCP count focused validation:
  `uv run python -m pytest tests/test_stability_docs.py -q` passed with 2
  tests.
- MCP table focused validation:
  `uv run python -m pytest tests/test_stability_docs.py -q` passed with 3
  tests after adding live-registry membership coverage for the stability table.
- Focused lint and typing:
  `uv run python -m ruff check tests/test_stability_docs.py` and
  `uv run python -m pyright tests/test_stability_docs.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.50 percent. Tests: 3506 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Added a schema source-map guard as the next incremental step toward generated
  JSON Schema.
- Added `scripts/check_schema_sources.py`, which traces every top-level
  `docs/recon-schema.json` property to a `TenantInfo` dataclass field or an
  explicit formatter, static-envelope, batch-mode, or explain-mode source.
- Wired `schema-sources` into `scripts/check.py` as a fast core stage.
- Added `tests/test_schema_sources.py` for current-schema coverage, explicit
  formatter-derived fields, unknown schema fields, unrepresented model fields,
  and stale special-source declarations.
- Updated roadmap, changelog, engineering practices, current-state analysis,
  and local loop skills to keep this as generator prep rather than claiming the
  full schema generator is complete.
- Focused validation:
  `uv run python scripts/check_schema_sources.py` passed, and
  `uv run python -m pytest tests/test_schema_sources.py tests/test_json_schema_file.py tests/test_markdown_links.py -q`
  passed with 28 tests.
- Focused lint and typing:
  `uv run python -m ruff check scripts/check_schema_sources.py tests/test_schema_sources.py scripts/check.py`
  and
  `uv run python -m pyright scripts/check_schema_sources.py tests/test_schema_sources.py scripts/check.py`
  passed.
- Fast local gate:
  `uv run python scripts/check.py --fast` passed with the new `schema-sources`
  stage included.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.50 percent. Tests: 3503 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Added generated maintainer context-packet metadata to the surface inventory.
- Extended `scripts/generate_surface_inventory.py` so
  `agent_surfaces.maintainer_context_packet` records the shared loop-contract
  files, their roles, and path-existence checks.
- Regenerated `docs/surface-inventory.json` and
  `src/recon_tool/data/surface-inventory.json` so the MCP
  `recon://surface-inventory` resource exposes the same packet.
- Updated README, MCP docs, docs index, maintainer-loop runbook, roadmap,
  changelog, current-state analysis, and local loop skills to keep the packet
  patch-level and non-contractual.
- Focused validation:
  `uv run python -m pytest tests/test_surface_inventory.py tests/test_schema_resource.py tests/test_maintainer_loop_runbook.py tests/test_markdown_links.py -q`
  passed with 20 tests.
- Focused lint and typing:
  `uv run python -m ruff check scripts/generate_surface_inventory.py tests/test_surface_inventory.py tests/test_schema_resource.py tests/test_maintainer_loop_runbook.py`
  and
  `uv run python -m pyright scripts/generate_surface_inventory.py tests/test_surface_inventory.py tests/test_schema_resource.py tests/test_maintainer_loop_runbook.py`
  passed.
- Generated inventory check:
  `uv run python scripts/generate_surface_inventory.py --check --check-cli-surface`
  passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.52 percent. Tests: 3498 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Added a PLR size-rule ratchet to the local CI mirror.
- Added `scripts/check_plr_ratchet.py`, which runs Ruff over `PLR0911`,
  `PLR0912`, `PLR0913`, and `PLR0915`, parses the statistics output, and fails
  only when current debt exceeds the recorded ceilings.
- Wired the ratchet into `scripts/check.py` as a fast core stage.
- Added `tests/test_plr_ratchet.py` for statistics parsing, missing-rule
  defaults, and regression detection.
- Updated engineering practices, roadmap, changelog, current-state analysis,
  and local loop skills to describe the ratchet as regression prevention rather
  than instant full PLR enforcement.
- Focused validation:
  `uv run python -m pytest tests/test_plr_ratchet.py tests/test_markdown_links.py -q`
  passed with 4 tests.
- Focused lint and typing:
  `uv run python -m ruff check scripts/check_plr_ratchet.py tests/test_plr_ratchet.py scripts/check.py`
  and
  `uv run python -m pyright scripts/check_plr_ratchet.py tests/test_plr_ratchet.py scripts/check.py`
  passed.
- Ratchet smoke:
  `uv run python scripts/check_plr_ratchet.py` passed at `PLR0911` 22/22,
  `PLR0912` 14/14, `PLR0913` 51/51, and `PLR0915` 9/9.
- Fast local gate:
  `uv run python scripts/check.py --fast` passed with the new `plr-ratchet`
  stage included.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Pytest reported 3498 passed, 5 skipped, 4 deselected, with 86.52 percent
  coverage.
- External spend: 0 USD.
- Hardened release-readiness commit hygiene for local stacks.
- `scripts/release_readiness.py` now checks every commit in `origin/main..HEAD`
  when the branch is ahead, falls back to `HEAD` otherwise, and rejects
  attribution markers, em dashes, and pictographic symbols.
- Added focused tests for ahead-stack attribution detection and pictographic
  symbol detection.
- Updated changelog, engineering practices, current-state analysis, and local
  loop skills.
- Focused validation:
  `uv run python -m pytest tests/test_release_readiness.py tests/test_markdown_links.py -q`
  passed with 13 tests.
- Focused lint and typing:
  `uv run python -m ruff check scripts/release_readiness.py tests/test_release_readiness.py`
  and
  `uv run python -m pyright scripts/release_readiness.py tests/test_release_readiness.py`
  passed.
- Readiness smoke:
  `uv run python scripts/release_readiness.py --allow-dirty` passed, with the
  expected dirty-worktree warning during this edit cycle.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.50 percent. Tests: 3495 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Added advisory diff coverage as a maintainer-local signal.
- Added `scripts/diff_coverage.py` to combine Coverage.py JSON with a unified
  diff, count only changed executable Python lines, report missing changed
  lines by file, return success for documentation-only diffs, and optionally
  fail under a caller-supplied threshold.
- Added `tests/test_diff_coverage.py` for diff parsing, measured-line
  filtering, Coverage.py JSON loading, documentation-only no-op behavior, and
  threshold failures.
- Updated engineering practices, roadmap, changelog, current-state analysis,
  and local loop skills to keep diff coverage advisory rather than a blocking
  gate.
- Focused validation:
  `uv run python -m pytest tests/test_diff_coverage.py tests/test_markdown_links.py -q`
  passed with 6 tests.
- Focused lint and typing:
  `uv run python -m ruff check scripts/diff_coverage.py tests/test_diff_coverage.py`
  and
  `uv run python -m pyright scripts/diff_coverage.py tests/test_diff_coverage.py`
  passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.49 percent. Tests: 3493 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Hardened the hand-maintained JSON Schema drift guard for model-backed nested
  `$defs`.
- Added dataclass field-set checks for `BIMIIdentity`, `CertBurst`,
  `CertSummary`, `ChainMotif`, `DeltaReport`, `EvidenceRecord`,
  `InfrastructureCluster`, `InfrastructureClusterReport`, `NodeConflict`,
  `NodeEvidence`, `NodeUnitCounterfactual`, `PosteriorObservation`,
  `SurfaceAttribution`, and `UnclassifiedCnameChain`, with explicit exceptions
  for schema-only or intentionally omitted JSON fields.
- Updated roadmap, changelog, current-state analysis, and local loop skills to
  record this as an incremental drift guard, not full schema generation.
- Focused validation:
  `uv run python -m pytest tests/test_json_schema_file.py -q` passed with
  22 tests.
- Focused lint and typing:
  `uv run python -m ruff check tests/test_json_schema_file.py` and
  `uv run python -m pyright tests/test_json_schema_file.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.51 percent. Tests: 3488 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Added `docs/maintainer-loop-runbook.md` for optional maintainer loops around
  CI failure triage, private calibration, and fingerprint proposal work.
- The runbook pins context packet loading, ignored local state, deterministic
  gates, explicit stop conditions, spend tracking from 0 USD, and maintainer
  review for semantic changes.
- Linked the runbook from the docs index and PV2 maintainer-validation doc, and
  marked the roadmap research item done.
- Added `tests/test_maintainer_loop_runbook.py` to keep the loop shapes,
  preflight/hygiene gates, spend rule, local state path, and agentic boundary in
  place.
- Focused validation:
  `uv run python -m pytest tests/test_maintainer_loop_runbook.py tests/test_markdown_links.py -q`
  passed with 5 tests.
- Focused lint and typing:
  `uv run python -m ruff check tests/test_maintainer_loop_runbook.py` and
  `uv run python -m pyright tests/test_maintainer_loop_runbook.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.50 percent. Tests: 3474 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Added a local corpus preflight to the maintainer calibration bundle.
- The preflight rejects a missing or too-small consolidated corpus, rejects
  runs where every stratum is below `--min-cell`, and reports eligible versus
  suppressed strata in dry runs before any network harness starts.
- Extended calibration bundle metadata with consolidated, eligible-strata, and
  suppressed-strata counts.
- Updated validation docs, roadmap, changelog, README assurance notes, current
  state analysis, and local loop skills.
- Focused validation:
  `uv run python -m pytest tests/test_run_calibration_bundle.py -q` passed with
  15 tests.
- Focused lint and typing:
  `uv run python -m ruff check validation/run_calibration_bundle.py tests/test_run_calibration_bundle.py`
  and
  `uv run python -m pyright validation/run_calibration_bundle.py tests/test_run_calibration_bundle.py`
  passed.
- Validation hygiene:
  `uv run python scripts/check_validation_hygiene.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.50 percent. Tests: 3470 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Added PR-scoped ClusterFuzzLite parser-boundary fuzzing.
- Added `.clusterfuzzlite` Python build integration with a digest-pinned
  `base-builder-python` image.
- Added a Python Atheris fuzzer for local domain normalization, control-byte
  stripping, cache serialization/deserialization, and formatter serialization.
- Added a read-only, SHA-pinned, bounded ClusterFuzzLite workflow using the
  pinned `google/clusterfuzzlite` v1 action SHA.
- Added local tests for ClusterFuzzLite config, workflow bounds, and fuzzer seed
  inputs.
- Focused validation:
  `uv run python -m pytest tests/test_clusterfuzzlite_integration.py tests/test_scorecard_posture.py tests/test_workflow_pins.py -q`
  passed with 16 tests.
- Focused lint and typing:
  `uv run python -m ruff check fuzz/recon_input_fuzzer.py tests/test_clusterfuzzlite_integration.py`
  and `uv run python -m pyright tests/test_clusterfuzzlite_integration.py`
  passed.
- Workflow pin check:
  `uv run python scripts/check_workflow_pins.py` passed.
- Shell syntax check:
  `C:\Program Files\Git\bin\bash.exe -n .clusterfuzzlite/build.sh` passed.
- Docker validation note: Docker Desktop's Linux engine was unavailable in this
  environment, so the ClusterFuzzLite container build was not run locally.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.50 percent. Tests: 3467 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Added the `recon://surface-inventory` MCP resource.
- Packaged the generated surface inventory beside the JSON schema so MCP
  clients can read local CLI, MCP, JSON-schema, and agent guidance context
  without repository-file access.
- Extended the surface-inventory generator to include MCP resource metadata.
- Added drift and registration tests for the packaged inventory copy.
- Focused validation:
  `uv run python -m pytest tests/test_surface_inventory.py tests/test_server_resources.py tests/test_schema_resource.py tests/test_package_invariants.py tests/test_mcp_tool_annotations.py -q`
  passed with 32 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_introspection.py src/recon_tool/surface_inventory.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py tests/test_server_resources.py tests/test_schema_resource.py tests/test_package_invariants.py tests/test_mcp_tool_annotations.py`
  and
  `uv run python -m pyright src/recon_tool/server_introspection.py src/recon_tool/surface_inventory.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py tests/test_server_resources.py tests/test_schema_resource.py tests/test_package_invariants.py tests/test_mcp_tool_annotations.py`
  passed.
- Generated-doc checks:
  `uv run python scripts/generate_surface_inventory.py --check` and
  `uv run python scripts/generate_surface_inventory.py --check-cli-surface`
  passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.52 percent. Tests: 3462 passed, 6 skipped, 4 deselected.
- External spend: 0 USD.
- Added explicit job timeouts to every GitHub Actions workflow.
- Set bounded `timeout-minutes` values across CI, CodeQL, Scorecard, secrets
  scan, release, and the existing mutation gate.
- Added a Scorecard posture regression test that parses every workflow and fails
  if any job lacks a bounded integer timeout.
- Updated supply-chain docs and state notes to record the job-timeout contract.
- Focused validation:
  `uv run python -m pytest tests/test_scorecard_posture.py tests/test_release_workflow_contract.py tests/test_workflow_pins.py -q`
  passed with 28 tests.
- Focused lint and typing:
  `uv run python -m ruff check tests/test_scorecard_posture.py` and
  `uv run python -m pyright tests/test_scorecard_posture.py` passed.
- Workflow pin check:
  `uv run python scripts/check_workflow_pins.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.46 percent. Tests: 3457 passed, 6 skipped, 4 deselected.
- External spend: 0 USD.
- Hardened GitHub Actions checkout credential handling.
- Set `persist-credentials: false` on every `actions/checkout` step so workflow
  tokens are not left in local Git config after checkout.
- Added a Scorecard posture regression test that parses every workflow and fails
  if a checkout step persists credentials.
- Updated supply-chain docs and state notes to record the checkout credential
  contract.
- Focused validation:
  `uv run python -m pytest tests/test_scorecard_posture.py tests/test_release_workflow_contract.py tests/test_workflow_pins.py -q`
  passed with 27 tests.
- Focused lint and typing:
  `uv run python -m ruff check tests/test_scorecard_posture.py` and
  `uv run python -m pyright tests/test_scorecard_posture.py` passed.
- Workflow pin check:
  `uv run python scripts/check_workflow_pins.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.46 percent. Tests: 3457 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Tightened Scorecard-facing workflow-token posture tests.
- Added a repository-wide assertion that every GitHub Actions workflow defaults
  to top-level read-only token permissions.
- Added an allowlist for elevated job scopes so `id-token`, `attestations`,
  `security-events`, and release write permissions stay tied to named jobs.
- Focused validation:
  `uv run python -m pytest tests/test_scorecard_posture.py tests/test_release_workflow_contract.py tests/test_workflow_pins.py -q`
  passed with 26 tests.
- Focused lint and typing:
  `uv run python -m ruff check tests/test_scorecard_posture.py` and
  `uv run python -m pyright tests/test_scorecard_posture.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.49 percent. Tests: 3456 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Centralized validation-runner path safety.
- Added `validation.run_path_safety` for safe run-stamp validation and contained
  output-root child resolution.
- Switched the calibration bundle and public paper-number reproduction runners
  to the shared helper so their artifact-boundary behavior cannot drift.
- Added direct helper tests for accepted stamps, rejected stamps, contained paths,
  and escaped child paths.
- Focused validation:
  `uv run python -m pytest tests/test_run_path_safety.py tests/test_run_calibration_bundle.py tests/test_reproduce_paper_numbers.py -q`
  passed with 37 tests.
- Focused lint and typing:
  `uv run python -m ruff check validation/run_path_safety.py validation/run_calibration_bundle.py validation/reproduce_paper_numbers.py tests/test_run_path_safety.py tests/test_run_calibration_bundle.py tests/test_reproduce_paper_numbers.py`
  and
  `uv run python -m pyright validation/run_path_safety.py validation/run_calibration_bundle.py validation/reproduce_paper_numbers.py tests/test_run_path_safety.py tests/test_run_calibration_bundle.py tests/test_reproduce_paper_numbers.py`
  passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.49 percent. Tests: 3455 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Hardened the public paper-number reproduction runner's run-directory handling.
- Added safe run-stamp validation and output-root containment to
  `validation.reproduce_paper_numbers`, matching the maintainer-local calibration
  bundle rule.
- Added focused regression coverage for unsafe stamps and safe resolved dry-run
  directories.
- Updated the validation docs, roadmap, changelog, and state analysis to record
  the public reproduction path-containment contract.
- Focused validation:
  `uv run python -m pytest tests/test_reproduce_paper_numbers.py tests/test_run_calibration_bundle.py -q`
  passed with 23 tests.
- Focused lint and typing:
  `uv run python -m ruff check validation/reproduce_paper_numbers.py tests/test_reproduce_paper_numbers.py`
  and
  `uv run python -m pyright validation/reproduce_paper_numbers.py tests/test_reproduce_paper_numbers.py`
  passed.
- Validation hygiene:
  `uv run python scripts/check_validation_hygiene.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.51 percent. Tests: 3441 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Hardened the maintainer-local calibration bundle runner's run-directory
  handling.
- Added a safe run-stamp validator and containment check so `--stamp` cannot
  traverse outside `--output-root`.
- Added focused regression coverage for unsafe stamps and safe resolved run
  directories.
- Focused validation:
  `uv run python -m pytest tests/test_run_calibration_bundle.py -q` passed with
  12 tests.
- Focused lint and typing:
  `uv run python -m ruff check validation/run_calibration_bundle.py tests/test_run_calibration_bundle.py`
  and
  `uv run python -m pyright validation/run_calibration_bundle.py tests/test_run_calibration_bundle.py`
  passed.
- Validation hygiene:
  `uv run python scripts/check_validation_hygiene.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.51 percent. Tests: 3433 passed, 6 skipped, 4 deselected.
- External spend: 0 USD.
- Extended precise MCP output schemas to `reevaluate_domain`.
- Added the nested `LookupResult` `TypedDict` family for the cached-domain
  re-evaluation object returned by `format_tenant_dict`.
- Kept the runtime payload compatible while adding `evidence: []` on the MCP
  re-evaluation path when the cached lookup has no evidence, so every advertised
  required key is present.
- Regenerated `docs/surface-inventory.json` so the derived inventory records the
  full lookup result schema for `reevaluate_domain`.
- Focused validation:
  `uv run python -m pytest tests/test_mcp_structured_output.py tests/test_server_agentic.py -q`
  passed with 39 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_ephemeral.py tests/test_mcp_structured_output.py tests/test_server_agentic.py`
  and
  `uv run python -m pyright src/recon_tool/server_ephemeral.py tests/test_mcp_structured_output.py tests/test_server_agentic.py`
  passed.
- Surface inventory and file-size checks:
  `uv run python scripts/generate_surface_inventory.py --check` and
  `uv run python scripts/check_file_size.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.49 percent. Tests: 3425 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Extended precise MCP output schemas to `analyze_posture`.
- Added typed observation and explanation envelopes for the bare list,
  profiled, explained, and profiled-explained response variants.
- Preserved the existing compatibility split: unprofiled non-explain calls
  still return a bare list, while profile or explain calls return envelopes.
- Regenerated `docs/surface-inventory.json` so the derived inventory records the
  `analyze_posture` union schema and nested definitions.
- Focused validation:
  `uv run python -m pytest tests/test_mcp_structured_output.py tests/test_mcp_introspection.py tests/test_explain_integration.py tests/test_surface_inventory.py -q`
  passed with 87 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_posture.py tests/test_mcp_structured_output.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  and
  `uv run python -m pyright src/recon_tool/server_posture.py tests/test_mcp_structured_output.py`
  passed.
- Surface inventory check:
  `uv run python scripts/generate_surface_inventory.py --check` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.35 percent. Tests: 3424 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Extended precise MCP output schemas to `discover_fingerprint_candidates`.
- Added `FingerprintCandidate` and `FingerprintCandidateSample` `TypedDict`
  envelopes for suffix counts and sample unclassified CNAME chains.
- Regenerated `docs/surface-inventory.json` so the derived inventory records the
  discovery candidate output-schema fields and nested sample definition.
- Focused validation:
  `uv run python -m pytest tests/test_mcp_structured_output.py tests/test_surface_attribution.py tests/test_surface_inventory.py -q`
  passed with 43 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_introspection.py tests/test_mcp_structured_output.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  and
  `uv run python -m pyright src/recon_tool/server_introspection.py tests/test_mcp_structured_output.py`
  passed.
- Surface inventory check:
  `uv run python scripts/generate_surface_inventory.py --check` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.36 percent. Tests: 3423 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Extended precise MCP output schemas to the exposure report tools:
  `assess_exposure`, `find_hardening_gaps`, and `compare_postures`.
- Added nested `TypedDict` envelopes for evidence references, observability,
  email, identity, infrastructure, hardening controls, gaps, metrics,
  differences, and relative assessments.
- Kept formatter behavior unchanged by casting the existing formatter outputs at
  the MCP boundary.
- Regenerated `docs/surface-inventory.json` so the derived inventory records the
  exposure report output-schema fields and nested definitions.
- Focused validation:
  `uv run python -m pytest tests/test_mcp_structured_output.py tests/test_exposure_server.py tests/test_exposure.py tests/test_surface_inventory.py -q`
  passed with 82 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_posture.py tests/test_mcp_structured_output.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  and
  `uv run python -m pyright src/recon_tool/server_posture.py tests/test_mcp_structured_output.py`
  passed.
- Surface inventory check:
  `uv run python scripts/generate_surface_inventory.py --check` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.36 percent. Tests: 3422 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Extended precise MCP output schemas to `get_posteriors`.
- Added `PosteriorBlockResult`, `PosteriorNodeSummary`, and
  `UnitCounterfactualSummary` `TypedDict` envelopes for the Bayesian posterior
  readout.
- Left `explain_dag` as narrative text and kept the larger posture report tools
  on permissive schemas for separate compatibility passes.
- Regenerated `docs/surface-inventory.json` so the derived inventory records the
  new posterior output-schema fields and nested definitions.
- Focused validation:
  `uv run python -m pytest tests/test_mcp_structured_output.py tests/test_server_bayesian_tools.py tests/test_fusion_robustness.py tests/test_surface_inventory.py -q`
  passed with 50 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_introspection.py tests/test_mcp_structured_output.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  and
  `uv run python -m pyright src/recon_tool/server_introspection.py tests/test_mcp_structured_output.py`
  passed.
- Surface inventory check:
  `uv run python scripts/generate_surface_inventory.py --check` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.31 percent. Tests: 3421 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Extended precise MCP output schemas to `explain_signal`.
- Added typed static-definition and domain-evaluation variants with
  `SignalTriggerConditions` and `SignalEvidenceSummary`.
- Preserved the existing response split: no-domain calls return only the signal
  definition, while domain calls return the evaluation fields as a superset.
- Regenerated `docs/surface-inventory.json` so the derived inventory records the
  new `explain_signal` union schema and nested definitions.
- Focused validation:
  `uv run python -m pytest tests/test_mcp_structured_output.py tests/test_mcp_introspection.py tests/test_explain_integration.py tests/test_surface_inventory.py -q`
  passed with 83 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_introspection.py tests/test_mcp_structured_output.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  and
  `uv run python -m pyright src/recon_tool/server_introspection.py tests/test_mcp_structured_output.py`
  passed.
- Surface inventory check:
  `uv run python scripts/generate_surface_inventory.py --check` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.27 percent. Tests: 3419 passed, 6 skipped, 4 deselected.
- External spend: 0 USD.
- Extended precise MCP output schemas to the compact agent-facing posture
  helpers: `test_hypothesis` and `simulate_hardening`.
- Added `HypothesisAssessmentResult`, `HardeningSimulationResult`, and
  `SimulatedGapSummary` `TypedDict` envelopes, with enums for hypothesis
  likelihood and confidence.
- Left `analyze_posture`, `assess_exposure`, `find_hardening_gaps`,
  `compare_postures`, `get_posteriors`, and `reevaluate_domain` on permissive
  schemas for separate compatibility passes because their object graphs are
  larger.
- Regenerated `docs/surface-inventory.json` so the derived inventory records the
  new helper output-schema fields and nested definition count.
- Focused validation:
  `uv run python -m pytest tests/test_mcp_structured_output.py tests/test_server_agentic.py tests/test_surface_inventory.py -q`
  passed with 42 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_posture.py tests/test_mcp_structured_output.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  and
  `uv run python -m pyright src/recon_tool/server_posture.py tests/test_mcp_structured_output.py`
  passed.
- Surface inventory check:
  `uv run python scripts/generate_surface_inventory.py --check` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.22 percent. Tests: 3418 passed, 6 skipped, 4 deselected.
- External spend: 0 USD.
- Extended precise MCP output schemas to the graph data tools:
  `cluster_verification_tokens`, `get_infrastructure_clusters`, and
  `export_graph`.
- Added `TypedDict` envelopes for shared verification peers, graph cluster
  summaries, graph edges, and the three returned object shapes.
- Kept `chain_lookup` as narrative text and left posture plus inference tools on
  the permissive Phase 1 schemas for separate compatibility passes.
- Added a disclaimer to the skipped `export_graph` branch so every runtime
  branch satisfies the advertised `GraphExportEnvelope`.
- Regenerated `docs/surface-inventory.json` so the derived inventory records the
  new graph output-schema definition counts.
- Focused validation:
  `uv run python -m pytest tests/test_surface_inventory.py tests/test_mcp_structured_output.py tests/test_mcp_graph_tools.py -q`
  passed with 27 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_graph.py tests/test_mcp_structured_output.py tests/test_mcp_graph_tools.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  and
  `uv run python -m pyright src/recon_tool/server_graph.py tests/test_mcp_structured_output.py`
  passed.
- Surface inventory check:
  `uv run python scripts/generate_surface_inventory.py --check` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.23 percent. Tests: 3418 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Extended precise MCP output schemas to the three simple ephemeral-fingerprint
  session tools: `inject_ephemeral_fingerprint`, `list_ephemeral_fingerprints`,
  and `clear_ephemeral_fingerprints`.
- Left `reevaluate_domain` on the permissive Phase 1 schema because it returns
  the full lookup object and needs a separate compatibility pass.
- Added structured-output tests for `EphemeralInjectionResult`,
  `EphemeralFingerprintSummary`, and `EphemeralClearResult`.
- Regenerated `docs/surface-inventory.json` so the derived inventory records the
  new ephemeral output-schema definition counts.
- Focused validation:
  `uv run python -m pytest tests/test_surface_inventory.py tests/test_mcp_structured_output.py tests/test_ephemeral_fingerprints.py tests/test_server_agentic.py -q`
  passed with 72 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_ephemeral.py tests/test_mcp_structured_output.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  and
  `uv run python -m pyright src/recon_tool/server_ephemeral.py tests/test_mcp_structured_output.py`
  passed.
- Surface inventory check:
  `uv run python scripts/generate_surface_inventory.py --check` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.22 percent. Tests: 3417 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Added precise `TypedDict` MCP output item schemas for the no-network catalog
  list tools: `FingerprintSummary` for `get_fingerprints`, and `SignalSummary`
  plus `SignalMetadataSummary` for `get_signals`.
- Kept the returned payloads unchanged while making FastMCP advertise concrete
  `outputSchema` fields instead of generic object items for those two lists.
- Added structured-output tests that inspect `mcp.list_tools()` and confirm the
  catalog list schemas reference the new `$defs` entries and required fields.
- Regenerated `docs/surface-inventory.json` so the derived MCP inventory records
  the new output-schema definition counts for both catalog tools.
- Updated `docs/mcp.md` and `docs/roadmap.md` to record this as the first
  precise-schema Phase 2 slice, not a complete migration for every data tool.
- Focused validation:
  `uv run python -m pytest tests/test_surface_inventory.py tests/test_mcp_structured_output.py tests/test_mcp_introspection.py tests/test_mcp_tool_annotations.py -q`
  passed with 42 tests.
- Focused lint and typing:
  `uv run python -m ruff check src/recon_tool/server_introspection.py tests/test_mcp_structured_output.py scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  and
  `uv run python -m pyright src/recon_tool/server_introspection.py tests/test_mcp_structured_output.py`
  passed.
- Surface inventory check:
  `uv run python scripts/generate_surface_inventory.py --check` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.16 percent. Tests: 3415 passed, 6 skipped, 4 deselected.
- External spend: 0 USD.
- Added the `tm_to_azurefd_to_msedge` built-in chain motif for complete
  Traffic Manager to Azure Front Door to Microsoft Edge CNAME chains.
- Kept the existing pairwise Microsoft motifs intact. The new motif adds a
  complete-chain observation when all three ordered markers appear in the same
  chain.
- Added regressions proving the triad motif loads, fires on a fictional
  `trafficmanager.net` to `azurefd.net` to `t-msedge.net` chain, and does not
  fire when the first two markers are reversed.
- Added `validation/2026-06-19-msedge-triad-motif.md` with a public
  before/after candidate-chain delta: the triad motif count moves from 0 to 1
  while the existing pairwise motifs still fire.
- Focused validation:
  `uv run python -m pytest tests/test_motifs.py tests/test_validation_hygiene.py -q`
  passed with 25 tests.
- Focused lint:
  `uv run python -m ruff check tests/test_motifs.py` passed.
- Validation hygiene:
  `uv run python scripts/check_validation_hygiene.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.18 percent. Tests: 3413 passed, 6 skipped, 4 deselected.
- External spend: 0 USD.
- Added a high-confidence Supabase `cname_target` fingerprint from the official
  custom-domain docs. The rule attributes branded CNAMEs that terminate at a
  Supabase project hostname without claiming database contents or plan details.
- Updated cloud-vendor classification so Supabase appears as its own cloud
  vendor in rollups rather than a generic infrastructure marker.
- Added regressions proving a fictional CNAME chain ending at a Supabase project
  hostname loads, classifies as application-layer Supabase evidence, and does
  not create a separate infrastructure attribution.
- Added `validation/2026-06-19-supabase-cname-target.md` to record the
  official-doc rationale and the decision not to fingerprint generic
  `_acme-challenge` TXT records.
- Focused validation:
  `uv run python -m pytest tests/test_surface_attribution.py tests/test_fingerprints.py tests/test_multi_cloud_rollup.py tests/test_slug_category_invariant.py tests/test_cloud_vendor_coverage.py tests/test_validation_hygiene.py -q`
  passed with 96 tests.
- Focused lint:
  `uv run python -m ruff check src/recon_tool/formatter_classify_tables.py tests/test_surface_attribution.py tests/test_fingerprints.py tests/test_multi_cloud_rollup.py`
  passed.
- Fingerprint validation:
  `uv run python scripts/validate_fingerprint.py src/recon_tool/data/fingerprints/ --quiet`
  passed with 842 entries.
- Validation hygiene:
  `uv run python scripts/check_validation_hygiene.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.14 percent. Tests: 3411 passed, 6 skipped, 4 deselected.
- External spend: 0 USD.
- Converted the CrowdStrike TXT fingerprint to `match_mode: all`, using the
  canonical `^crowdstrike-falcon-site-verification=` prefix plus the broad
  literal only as same-record corroboration.
- Added `match_txt_all()` and updated TXT detector bookkeeping so same-record
  multiple-pattern matches are recorded for all-mode enforcement while the
  user-visible first-match behavior remains stable.
- Added regressions proving `contoso.com` with a canonical Falcon verification
  token still detects and `northwindtraders.com` with only a generic
  CrowdStrike TXT mention does not.
- Added `validation/2026-06-19-crowdstrike-match-mode.md` with before/after
  audit counts and focused validation commands.
- Focused validation:
  `uv run python -m pytest tests/test_fingerprints.py tests/test_sources/test_dns.py -q`
  passed with 72 tests.
- Focused lint:
  `uv run python -m ruff check src/recon_tool/fingerprints.py src/recon_tool/sources/dns_email.py tests/test_fingerprints.py tests/test_sources/test_dns.py`
  passed.
- Fingerprint audit after the change reports `match modes: all=1, any=840`
  and one `already_all` entry.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.15 percent. Tests: 3411 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Created the active goal for autonomous roadmap progress.
- Inventoried 103 markdown files across root docs, validation reports, agent
  integrations, examples, packaging, and test documentation.
- Confirmed `validation/corpus-private/` is absent in this checkout, so the
  top active roadmap item is blocked on maintainer-local private data.
- Initial full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.18 percent. Tests: 3363 passed, 5 skipped, 4 deselected.
- Created `CURRENT-STATE-ANALYSIS.md`, `PROGRESS-LOG.md`, and `SKILLS.md` as
  noncanonical maintainer-loop artifacts.
- Hardened `validation/render_calibration_memo.py` so the public memo boundary
  rejects target-looking domain names in aggregate JSON keys and memo titles.
- Added focused disclosure tests in `tests/test_render_calibration_memo.py`.
- Corrected low-risk doc drift in `AGENTS.md`, `docs/mcp.md`, and
  `docs/limitations.md`.
- Focused validation: `uv run python -m pytest tests/test_render_calibration_memo.py -q`
  passed with 10 tests.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.16 percent. Tests: 3365 passed, 6 skipped, 4 deselected.
- Started the second cycle from the roadmap's reference-grade repository track.
- Added `validation/reproduce_paper_numbers.py`, a one-command public
  no-private-data reproduction bundle for the paper's synthetic and proof
  evidence rows.
- Documented the command in `validation/README.md`, `docs/roadmap.md`,
  `docs/paper-outline.md`, and `docs/paper-draft.md`.
- Added `tests/test_reproduce_paper_numbers.py` covering manifest output,
  dry-run behavior, failure handling, and profile validation.
- Ran the smoke profile:
  `uv run python -m validation.reproduce_paper_numbers --profile smoke --stamp smoke-test`.
  It passed and wrote ignored artifacts under `validation/local/`.
- Focused validation: `uv run python -m pytest tests/test_reproduce_paper_numbers.py tests/test_render_calibration_memo.py -q`
  passed with 14 tests.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.15 percent. Tests: 3370 passed, 5 skipped, 4 deselected.
- Started the third cycle from the agent and surface-inventory drift guard
  track.
- Extended `scripts/generate_surface_inventory.py` so
  `docs/surface-inventory.json` now includes agent guidance files, client MCP
  config templates, Claude Code plugin manifest metadata, and live MCP approval
  sets derived from tool annotations.
- Corrected the Claude Code plugin approval note so it no longer claims every
  MCP tool is read-only. It now names the three local stateful tools and
  describes the read-only split.
- Added `tests/test_surface_inventory.py` coverage for agent guidance
  frontmatter, client config keys, manual approval defaults, and the stateful
  MCP tool set.
- Focused validation:
  `uv run python -m pytest tests/test_surface_inventory.py tests/test_mcp_tool_annotations.py -q`
  passed with 8 tests.
- Focused lint:
  `uv run python -m ruff check scripts/generate_surface_inventory.py tests/test_surface_inventory.py`
  passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.17 percent. Tests: 3371 passed, 5 skipped, 4 deselected.
- Started the fourth cycle from the roadmap's no-behavior-change Bayesian
  calibration data item.
- Added a top-level `calibration:` block to
  `src/recon_tool/data/bayesian_network.yaml` for `min_n_eff`,
  `evidence_n_eff_contrib`, and `conflict_n_eff_penalty`.
- Added `CalibrationSettings` to the loaded Bayesian network, with loader
  defaults for older test fixtures and strict positive finite validation.
- Updated inference and conflict provenance to use the loaded network
  calibration values while preserving the historical module constants for
  internal compatibility.
- Updated roadmap, correlation, traceability, mutation-gate, and validation
  helper docs so they describe the YAML-backed calibration shape.
- Focused validation:
  `uv run python -m pytest tests/test_bayesian_inference.py tests/test_bayesian_unit_math.py tests/test_bayesian_network_invariants.py tests/test_bayesian_hypothesis.py tests/test_bayesian_fuzz.py tests/test_bayesian_masked_units.py tests/test_adversarial_properties.py tests/test_bayesian_sensitivity.py -q`
  passed with 178 tests.
- Focused lint and traceability:
  `uv run python -m ruff check ...` passed, and
  `uv run python scripts/check_traceability.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.18 percent. Tests: 3376 passed, 6 skipped, 4 deselected.
- Started the fifth cycle from the roadmap's downstream skill and agent-author
  surface-reference item.
- Added generated `docs/cli-surface.md`, derived from the live Typer command
  tree with command anchors, child command lists, and parameter tables.
- Extended `scripts/generate_surface_inventory.py` with `--write-cli-surface`
  and `--check-cli-surface`, keeping the Markdown reference generated rather
  than manually maintained.
- Added `scripts/check.py` coverage for the CLI surface reference through a new
  `cli-surface-doc` stage.
- Updated README, docs index, roadmap, and changelog so the generated CLI
  reference is discoverable and the roadmap marks that part of the surface
  inventory work done.
- Added `tests/test_surface_inventory.py` coverage for CLI surface freshness,
  expected command content, ASCII output, and target-free output.
- Focused validation:
  `uv run python -m pytest tests/test_surface_inventory.py -q` passed with 9
  tests.
- Focused lint and generated-file checks passed:
  `uv run python -m ruff check scripts/generate_surface_inventory.py tests/test_surface_inventory.py scripts/check.py`
  and `uv run python scripts/generate_surface_inventory.py --check --check-cli-surface`.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.14 percent. Tests: 3380 passed, 5 skipped, 4 deselected.
- Started the sixth cycle from the remaining CLI surface release-note polish.
- Added `scripts/summarize_cli_surface_changes.py`, a maintainer-local comparer
  for generated `docs/surface-inventory.json` files that emits the
  changelog-ready `Tool surface changes:` line.
- The helper supports direct inventory paths, `--old-ref vX.Y.Z` for git-tag
  comparisons without shell redirection, and `--json` for structured release
  automation.
- Added `tests/test_summarize_cli_surface_changes.py` covering command deltas,
  flag deltas, no-change summaries, JSON output, argument validation, and git
  ref failures.
- Updated `docs/release-process.md` to require a `### Tool Surface Changes`
  entry per release and to document the helper.
- Updated `CHANGELOG.md` with the current no-runtime-CLI-change surface line and
  `docs/roadmap.md` to mark the CLI surface inventory release-note item done.
- Focused validation:
  `uv run python -m pytest tests/test_summarize_cli_surface_changes.py -q`
  passed with 7 tests.
- Focused lint:
  `uv run python -m ruff check scripts/summarize_cli_surface_changes.py tests/test_summarize_cli_surface_changes.py`
  passed.
- Helper smoke:
  `uv run python scripts/summarize_cli_surface_changes.py --old-ref HEAD`
  returned `Tool surface changes: no CLI command or flag changes.`
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.16 percent. Tests: 3387 passed, 5 skipped, 4 deselected.
- Started the seventh cycle from the good-first MCP resource consumption
  examples item.
- Expanded `docs/mcp.md` with no-network resource-read workflows for
  `recon://fingerprints`, `recon://signals`, `recon://profiles`, and
  `recon://schema`.
- The examples tell agents to inspect capability context before domain-analysis
  calls, to choose posture profiles only from explicit target type, to avoid
  treating missing fingerprints as absence evidence, and to validate JSON shapes
  from the local schema resource.
- Added `tests/test_mcp_tool_annotations.py` coverage that pins the new resource
  consumption examples and the key hedging rules.
- Updated `CHANGELOG.md` and `docs/roadmap.md` to mark the MCP resource example
  item complete.
- Focused validation:
  `uv run python -m pytest tests/test_mcp_tool_annotations.py tests/test_server_resources.py tests/test_schema_resource.py -q`
  passed with 16 tests.
- Focused lint:
  `uv run python -m ruff check tests/test_mcp_tool_annotations.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.18 percent. Tests: 3387 passed, 6 skipped, 4 deselected.
- Started the eighth cycle from the user's Scorecard request.
- Queried the public Scorecard API for `github.com/blisspixel/recon`; current
  published result is score 6.1 at commit
  `fc976bcab492232eb35111a26ea8deb14aa00b7e`.
- Confirmed local-file actionable gaps are primarily future Signed-Releases
  posture and monitored release-integrity behavior. Branch protection,
  code-review score, maintained score, contributors, and CII badge require
  repository settings, PR history, elapsed time, outside contributors, or
  external OpenSSF badge enrollment.
- Updated `.github/workflows/release.yml` so PyPI publishing and GitHub release
  publication wait for build-provenance attestation.
- Added an `export-attestations` release job that downloads GitHub's signed
  attestation bundles for the sealed `dist/` artifacts, exports
  `recon-tool-<version>.intoto.jsonl`, uploads it as a workflow artifact, and
  attaches it to the GitHub Release.
- Updated release workflow contract tests and Scorecard posture tests to require
  the provenance export job, `.intoto.jsonl` asset, and GitHub Release
  attachment.
- Updated supply-chain, release-process, roadmap, and changelog docs to describe
  the fail-closed provenance path and future Scorecard-recognized release asset.
- Focused validation:
  `uv run python -m pytest tests/test_release_workflow_contract.py tests/test_release_workflow.py tests/test_scorecard_posture.py -q`
  passed with 26 tests.
- Focused lint and workflow pin checks passed:
  `uv run python -m ruff check tests/test_release_workflow_contract.py tests/test_release_workflow.py tests/test_scorecard_posture.py`
  and `uv run python scripts/check_workflow_pins.py`.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.16 percent. Tests: 3391 passed, 6 skipped, 4 deselected.
- External spend: 0 USD.
- Started the ninth cycle from the roadmap's automation-consumption docs item.
- Added `docs/automation-examples.md` covering single lookup, batch array, batch
  wrapper, NDJSON, delta, and cohort-summary JSON consumption.
- Updated docs and examples indexes so automation parser recipes are discoverable
  from the main docs tree and from `examples/`.
- Expanded `examples/sample-output.json` to the full required v2.0 lookup shape
  while preserving the fictional Northwind fields used by the SIEM examples.
- Added `tests/test_automation_examples.py` coverage that parses the committed
  JSON snippets, checks schema-required fields, and verifies batch error records
  through the runtime classifier.
- Focused validation:
  `uv run python -m pytest tests/test_automation_examples.py tests/test_batch_ndjson_schema.py tests/test_json_schema_file.py tests/test_siem_examples.py -q`
  passed with 59 tests.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.16 percent. Tests: 3396 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Started the tenth cycle from the roadmap's under-described fingerprint
  metadata item.
- Added official reference URLs for five high-confidence verification-token
  fingerprints: Monday.com, Zoom, Formstack, Coda, and Virtru.
- Tightened the short Formstack, Coda, and Virtru descriptions so they name the
  observable binding and retain the "does not prove active usage" hedge.
- Updated the advisory metadata richness audit to recognize account-binding,
  program-binding, and tenant-binding wording as scope narrowing.
- Added tests pinning the binding-language heuristic and the five shipped
  verification references.
- Focused validation:
  `uv run python -m pytest tests/test_metadata_coverage.py tests/test_fingerprints.py tests/test_package_invariants.py -q`
  passed with 56 tests.
- Focused lint and catalog checks passed:
  `uv run python -m ruff check scripts/check_metadata_coverage.py tests/test_metadata_coverage.py`,
  `python scripts/validate_fingerprint.py src/recon_tool/data/fingerprints/verifications.yaml --quiet`,
  and `uv run python scripts/check_metadata_coverage.py --report-richness`.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.16 percent. Tests: 3398 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Started the eleventh cycle from the roadmap's weak-area false-negative note.
- Added a `docs/weak-areas.md` section for custom DKIM selectors and branded
  email senders.
- The note clarifies that `No DKIM observed` means no match at probed selectors,
  not proof DKIM is absent, and keeps contributor guidance provider-specific
  rather than broad selector guessing.
- Added `tests/test_weak_areas_doc.py` to pin the DKIM weak-area language.
- Focused validation:
  `uv run python -m pytest tests/test_weak_areas_doc.py tests/test_markdown_links.py -q`
  passed with 2 tests.
- Focused lint:
  `uv run python -m ruff check tests/test_weak_areas_doc.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.15 percent. Tests: 3399 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Started the twelfth cycle from the roadmap's aggregate-only validation memo
  item.
- Ran `uv run python -m validation.reproduce_paper_numbers --profile smoke --stamp roadmap-aggregate-smoke-20260619`.
- The smoke bundle passed all five public steps: adversarial properties,
  differential verification, interval coverage, likelihood sensitivity, and
  layer ablation. It read no private corpora, required no default network, and
  spent 0 USD.
- Added `validation/2026-06-19-paper-reproduction-smoke.md` as a committed
  aggregate-only memo. Local manifest and per-step stdout/stderr remain under
  ignored scratch paths.
- Added a narrow `.gitignore` whitelist for the sanitized memo while leaving
  `validation/local/` ignored.
- Added `tests/test_public_validation_memo.py` to pin the disclosure controls,
  headline-result caveat, and validation-hygiene compliance.
- Focused validation:
  `uv run python -m pytest tests/test_public_validation_memo.py tests/test_validation_hygiene.py tests/test_reproduce_paper_numbers.py -q`
  passed with 12 tests.
- Focused lint and hygiene:
  `uv run python -m ruff check tests/test_public_validation_memo.py` and
  `python scripts/check_validation_hygiene.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.16 percent. Tests: 3401 passed, 5 skipped, 4 deselected.
- Post-whitelist focused validation:
  `uv run python -m pytest tests/test_public_validation_memo.py tests/test_validation_hygiene.py tests/test_reproduce_paper_numbers.py -q`
  and `python scripts/check_validation_hygiene.py` passed.
- External spend: 0 USD.
- Started the thirteenth cycle from the roadmap's parser/cache/MCP/formatter
  edge-test item.
- Added cache regression tests for pasted URL normalization to apex cache keys,
  top-level-only `cache_clear_all()` deletion, and the batch-only
  `shared_verification_tokens` non-persistence contract.
- Updated the roadmap, changelog, current-state analysis, and maintainer loop
  skills to record the cache-boundary contract.
- Focused validation:
  `uv run python -m pytest tests/test_cache_roundtrip.py tests/test_cache_stateful.py tests/test_cache_cli.py -q`
  passed with 50 tests.
- Focused lint:
  `uv run python -m ruff check tests/test_cache_roundtrip.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.14 percent. Tests: 3404 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
- Started the fourteenth cycle from the roadmap's sparse-result weak-area
  guidance item.
- Added a `docs/weak-areas.md` section for unclassified CNAME chain termini.
  The note explains that a reached but unmatched terminus is a fingerprint
  proposal queue, not a vendor claim, and routes contributors through
  `recon discover <domain>`, public vendor docs or repeated validation evidence,
  and negative tests.
- Added `tests/test_weak_areas_doc.py` coverage that pins the conservative
  wording.
- Focused validation:
  `uv run python -m pytest tests/test_weak_areas_doc.py tests/test_markdown_links.py tests/test_surface_attribution.py tests/test_unclassified_surface_panel.py -q`
  passed with 35 tests.
- Focused lint:
  `uv run python -m ruff check tests/test_weak_areas_doc.py` passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.15 percent. Tests: 3404 passed, 6 skipped, 4 deselected.
- External spend: 0 USD.
- Started the fifteenth cycle from the roadmap's vertical-baseline absence-rule
  item.
- Added `Identity` and `Security & Compliance` expected categories to the
  `high-value-target` profile. These use effective loaded fingerprint
  categories so observed Okta identity evidence and CrowdStrike security
  evidence suppress the corresponding absence observations.
- Corrected the correlation and stability docs to describe profile YAML files
  as the baseline-rule home, including `expected_categories` and
  `expected_motifs`.
- Added `tests/test_baseline_anomalies.py` coverage for the new profile
  expectations, the missing-security hedged observation, and the fully
  suppressed identity-plus-security case.
- Focused validation:
  `uv run python -m pytest tests/test_baseline_anomalies.py tests/test_profiles.py tests/test_server_resources.py -q`
  passed with 52 tests.
- Focused lint and catalog validation:
  `uv run python -m ruff check tests/test_baseline_anomalies.py` and
  `python scripts/validate_fingerprint.py src/recon_tool/data/fingerprints/ --quiet`
  passed.
- Final full local gate with `uv run python scripts/check.py`: pass.
  Coverage: 86.15 percent. Tests: 3408 passed, 5 skipped, 4 deselected.
- External spend: 0 USD.
