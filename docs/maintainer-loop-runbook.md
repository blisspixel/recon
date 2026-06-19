# Maintainer Loop Runbook

This runbook is for optional maintainer and agent loops around recon. It does
not change recon runtime behavior. recon remains a local CLI, library, JSON
producer, and MCP server; the loop is only a way to repeat maintainer work with
clear gates.

Use it only when all of these are true:

- the task repeats;
- the loop can read the same files and logs a maintainer would read;
- success is decided by a deterministic gate;
- target data and per-domain artifacts stay in ignored local paths;
- external spend is tracked and defaults to 0 USD;
- semantic changes still receive maintainer review.

Do not use a loop to change CPT values, fingerprints, schemas, release assets,
or distribution artifacts without a reviewed diff and the project gates that
normally protect that surface.

## Shared Loop Contract

Every loop uses the same four records:

1. **Context packet:** `README.md`, `AGENTS.md`, `docs/agentic-balance.md`,
   `docs/roadmap.md`, `docs/maintainer-validation.md`, `validation/README.md`,
   `PROGRESS-LOG.md`, and `SKILLS.md`.
2. **State file:** an ignored JSON file under `validation/local/`, such as
   `validation/local/maintainer-loop-state.json`, recording the latest command,
   outcome, commit, elapsed time, and spend.
3. **Gate:** one deterministic command or CI check that decides pass or fail.
4. **Stop condition:** pass, reproducible blocker, or reviewed issue or PR.

The state file is operational memory, not product memory. It must not contain
real apexes, organization names, tenant IDs, per-domain findings, or private
corpus paths outside the ignored local workspace.

## CI Failure Triage Loop

Use when a pull request or local branch has a failing check.

1. Refresh the context packet.
2. Read the failing job name, log excerpt, and changed files.
3. Reproduce the smallest failing command locally.
4. Patch only the code, test, or doc surface implicated by the failure.
5. Re-run the narrow failing gate.
6. Run `uv run python scripts/check.py` before claiming readiness.
7. Record the command, result, elapsed time, and spend in the ignored state
   file.

Stop when the failing check passes, the full local gate passes, or the failure
is not reproducible and an issue or PR comment captures the evidence.

## Private Calibration Loop

Use on a maintainer machine with `validation/corpus-private/` populated.

1. Refresh the context packet and confirm `docs/data-handling-policy.md`.
2. Run a no-network dry run:

   ```bash
   python -m validation.run_calibration_bundle --dry-run
   ```

3. Confirm the dry-run preflight reports a publishable consolidated corpus and
   at least one publishable stratum at the configured `--min-cell`.
4. Run the live bundle only if the preflight passes:

   ```bash
   python -m validation.run_calibration_bundle \
     --label "Aggregate Calibration Validation Memo"
   ```

5. Review `validation/runs-private/<stamp>/memo.md`.
6. Commit only aggregate counts, rates, intervals, quantiles, and deltas.
7. Run `uv run python scripts/check_validation_hygiene.py`.
8. Run `uv run python scripts/check.py` before claiming readiness.
9. Record run stamp, aggregate artifact names, commands, result, elapsed time,
   and spend in the ignored state file.

Stop when the aggregate memo passes hygiene review and the full local gate
passes, or when the bundle fails with enough logs to fix the harness without
touching private data.

## Fingerprint Proposal Loop

Use on local gap output, never on guessed vendors.

1. Refresh the context packet and read `docs/fingerprints.md` and
   `validation/README.md`.
2. Start from `validation/scan.py`, `validation/find_gaps.py`, or
   `validation/triage_candidates.py` output in ignored local paths.
3. Propose a catalog or motif patch only when the candidate has public vendor
   documentation or repeated aggregate-safe validation evidence.
4. Add negative tests for overmatch and sparse-result wording where relevant.
5. Run the narrow classifier or motif tests, then `uv run python scripts/check.py`
   before claiming readiness.
6. Record candidate slug, public reference, aggregate delta if available,
   commands, result, elapsed time, and spend in the ignored state file.

Stop when the proposal has tests and public evidence, or when the candidate is
rejected with the reason recorded.

## Spend Rule

Default spend is 0 USD. If a maintainer explicitly permits paid validation for
a loop, write the approved cap and current total into the ignored state file
before the paid action starts. The loop stops before the cap is exceeded.

## Review Rule

The loop can prepare a patch. It cannot dispose of semantic changes on its own.
Catalog entries, CPT edits, schema changes, release changes, and distribution
changes still need normal maintainer review and the same gates as hand-written
work.
