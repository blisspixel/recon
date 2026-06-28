# validation/

Live-validation workspace. The directory hosts the runners, the gap-analysis
tooling, and the fingerprint-discovery loop, plus a small fictional-example
corpus. **Real company names are gitignored.** Curate your own private corpus
locally and the .gitignore keeps it out of commits; see [Policy](#policy)
below.

## What's in here

Committed (generic tooling, no company names):

- `run_corpus.py`: batch runner. Calls `recon` across a corpus file, emits
  `results.json`, `summary.json`, `summary.md` per run.
- `find_gaps.py`: reads a run (single file or directory of per-domain JSON)
  and surfaces unclassified CNAME terminal suffixes ranked by frequency. The
  first half of the fingerprint-discovery loop.
- `triage_candidates.py`: programmatic filter on `gaps.json`: drops
  already-fingerprinted patterns, intra-org chains, and one-off noise. The
  output is the LLM-triage-ready candidate list.
- `diff_runs.py`: compares two run directories. Surfaces newly-attributed
  subdomains, lost slugs, and aggregate slug-frequency changes. Use after
  adding fingerprints to confirm uplift.
- `run_calibration_bundle.py`: maintainer-local wrapper around the reference,
  tenancy, and conformal calibration harnesses. Captures aggregate JSON without
  shell redirects and renders the checked memo under `runs-private/`.
- `audit_fingerprints.py`: no-network catalog audit. Reports metadata
  coverage and match-mode classification (`keep_any`, `review_for_all`,
  `tighten_patterns`).
- `render_calibration_memo.py`: reads aggregate JSON from private calibration
  runs, rejects target-identifying fields or unsuppressed small strata, and
  renders a reviewable aggregate memo.
- `reproduce_paper_numbers.py`: one-command public reproduction bundle for the
  paper's no-private-data numbers. It runs existing synthetic/proof harnesses and
  writes local artifacts under `validation/local/`.
- `corpus-example.txt`: fictional-company sample showing the format. Safe to
  commit because the names are made up.

Gitignored (your private workspace):

- `corpus-private/`: your curated test bed of real apexes, organized however
  you want (by region, vertical, customer type)
- `runs-private/`: output dirs from each run (results, gaps, diffs)
- `live_runs/`: default output from `run_corpus.py`
- `local/`: any other scratch space (notes, half-finished YAMLs, etc.)

## The fingerprint-discovery loop

```
USER runs recon on a target (single domain or corpus)
    ↓
RECON emits JSON including unclassified_cname_chains for unmatched chains
    ↓
PROGRAMMATIC FILTER drops noise: intra-org, already-fingerprinted, low-confidence
    ↓
LLM SKILL judges each survivor: real SaaS? tier? slug? category? YAML stanza?
    ↓
USER reviews, applies surface.yaml diff
    ↓
RECON re-runs the corpus, confirms uplift via diff_runs.py
```

Two entry points feed the same triage logic:

### Single-domain (incidental discovery during normal use)

```bash
recon contoso.com --json --include-unclassified > result.json
python validation/find_gaps.py --input result.json --output gaps.json
python validation/triage_candidates.py \
    --gaps gaps.json --fingerprints recon_tool/data/fingerprints/ \
    --output candidates.json
```

Then hand `candidates.json` to the
[`/recon-fingerprint-triage`](../agents/claude-code/skills/recon-fingerprint-triage/SKILL.md)
Claude Code skill, or to any agent reading the same input shape.

### Corpus run (deliberate, batch)

```bash
# Build (once) a private corpus
mkdir -p validation/corpus-private/
echo "contoso.com" > validation/corpus-private/saas-b2b.txt
# ... add more domains, organize as you like ...

# Run respectfully: concurrency 2 stays well under crt.sh's tolerance
python validation/run_corpus.py \
    --corpus validation/corpus-private/saas-b2b.txt \
    --concurrency 2

# Aggregate gaps across the run
python validation/find_gaps.py \
    --input validation/live_runs/<UTC-stamp>/ \
    --output validation/runs-private/<run>/gaps.json

# Filter to triage candidates
python validation/triage_candidates.py \
    --gaps validation/runs-private/<run>/gaps.json \
    --fingerprints recon_tool/data/fingerprints/ \
    --output validation/runs-private/<run>/candidates.json

# After adding fingerprints, verify uplift
python validation/diff_runs.py \
    --before <previous-run>/ \
    --after <new-run>/ \
    --output diff.json
```

### Polite-mode knobs for big runs

Both `recon` and `run_corpus.py` accept these:

- `--no-ct`: skip cert-transparency providers entirely. Discovery falls back
  to common-subdomain probes + apex CNAME walks. Use for runs of 1000+ domains
  where you want zero load on public CT services.
- `--concurrency N` (on `run_corpus.py`): how many `recon` invocations run in
  parallel. Default is 5; drop to 2 for large runs to stay polite to CT and
  DNS.

### Monthly cadence with `scan.py`

When you want to track catalog drift over time (e.g. "is recon's coverage
of our regional banks decaying?"), use the `scan.py` wrapper. It bundles
`recon batch` + `find_gaps` + `triage_candidates` + `diff_runs` into a
single timestamped invocation:

```bash
# First run of the month (writes to validation/runs-private/<UTC-stamp>/)
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --label monthly-2026-05 \
    --concurrency 4

# Next month: auto-diffs against the most recent prior scan
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --label monthly-2026-06
```

Each run directory ends up with `results.json`, `gaps.json`,
`candidates.json`, `diff.json` (when comparing to a prior run), and
`meta.json` capturing the scan timestamp, label, corpus size, and
candidate counts. Reading `meta.json` from any run answers "when was
this scanned, what was found?" without re-running.

For large monthly cadence, keep `--no-ct` on unless CT coverage is the point and
use modest concurrency. Real-company corpora live entirely under
`validation/corpus-private/` and never leave your machine; only generic patterns
surfaced for triage become candidate PRs.
If `--output-root` is inside this checkout, it must resolve under one of the
gitignored private validation workspaces: `validation/runs-private/`,
`validation/live_runs/`, or `validation/local/`. Operator-local paths outside
the checkout are allowed.

CT-enabled corpus sessions are intentionally partial and multi-session. Use
streaming NDJSON plus a wall-clock cap so a session finalizes aggregate artifacts
instead of being killed by the terminal or CI wrapper:

```bash
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --label c3-ct-session-1 \
    --ct \
    --concurrency 2 \
    --timeout 60 \
    --max-runtime 7200 \
    --no-compare
```

If a process was interrupted after `results.ndjson` already streamed records,
recover the aggregate artifacts without touching the network:

```bash
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --finalize-existing validation/runs-private/<UTC-stamp> \
    --ct \
    --no-compare
```

Partial runs write `meta.json` with `batch_completed`, `batch_timed_out`,
`results_records`, and the timeout settings. Diffing is skipped for partial
runs because comparing a partial session against a complete prior run is noisy.

After the public CT limiter cools down, retry only the domains whose CT attempt
was degraded in a prior session:

```bash
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --ct-retry-from validation/runs-private/<UTC-stamp> \
    --label c3-ct-retry-1 \
    --concurrency 2 \
    --timeout 60 \
    --max-runtime 7200 \
    --no-compare
```

The synthesized retry corpus is written under
`validation/runs-private/_inputs/` by default, keeping private apexes inside the
ignored validation workspace. `--ct-retry-from` accepts a run directory,
`results.ndjson`, or legacy `results.json`; malformed streamed tails are skipped
and repeated domains are retried once.

To understand progress across partial sessions without exposing target rows,
summarize private runs into aggregate JSON:

```bash
python validation/summarize_ct_sessions.py \
    validation/runs-private/<session-a> \
    validation/runs-private/<session-b> \
    --output validation/runs-private/c3-ct-session-summary.json
```

The summary reports raw outcome counts, best outcome by unique domain, and CT
data coverage. It emits run directory basenames and counts only. It does not
write domains, tenant IDs, organization names, or per-domain rows.

The 2026-06-26 C3 sequence is closed and documented in
[docs/c3-ct-validation-plan.md](../docs/c3-ct-validation-plan.md) and
`validation/2026-06-26-c3-ct-partial.md`. Do not use the old retry order as an
active queue unless a new concrete provider path or disclosure-safe validation
question changes the value calculation. Current publication packaging work is
tracked in [docs/external-writeup-plan.md](../docs/external-writeup-plan.md).

## Assurance and calibration harnesses

The statistical-assurance side of this directory (the dossier that reads
them: [docs/statistical-assurance.md](../docs/statistical-assurance.md)).
Synthetic harnesses run anywhere and their committed memos carry real
numbers; reference harnesses resolve real apexes, so their runs stay
maintainer-local and emit aggregates only
([docs/data-handling-policy.md](../docs/data-handling-policy.md)).

Synthetic / no-network (runnable by anyone, deterministic):

- `synthetic_calibration.py`: model-grounded calibration: samples worlds
  from the network's own priors/CPTs and checks reliability, ECE, Brier.
- `interval_coverage.py`: the v2.1.15 perturbation-coverage gate: the 80%
  interval against the CAL8 ±20% likelihood band, truth from an
  independent full-joint reference. Memo: `interval-coverage.md`.
- `differential_verification.py`: variable elimination cross-checked
  against naive full-joint enumeration over the enumerable evidence sweep.
- `adversarial_properties.py`: the machine-checked suppression-
  monotonicity proposition (correlation.md 4.3).
- `likelihood_sensitivity.py`: CAL8: posteriors/agreement under ±20%
  likelihood perturbation. Memo: `cal8-likelihood-sensitivity.md`.
- `drift_check.py`: the PV2 inference drift gate against
  `inference_baseline.json` (CI-gated).
- `layer_ablation.py`: what each layer adds: the Bayesian posterior vs
  slug-matching baselines (pooled and fired-regime), and Louvain vs
  connected components on planted partitions under bridging noise. Run
  and committed (fully synthetic): `layer-ablation.md`.
- `posture_distributions.py`: reads the engine's per-domain behaviour as
  distributions: information recovered (CAL10 entropy reduction) bucketed
  by observable hardening posture, and interval width vs evidence (the
  CAL7 over-confidence diagnostic). Pure aggregation unit-tested; the
  run is network/maintainer-local (aggregates only).

Reference-anchored / network (maintainer-local, aggregates only):

- `reference_calibration.py`: CAL3/CAL4: the email-policy posterior
  against the authoritative DMARC record, plus the held-out residual
  (the `dmarc_policy` unit masked, so predictor and label are disjoint).
  `--stratify-dir` for per-vertical cells. Memo:
  `reference-calibration.md`.
- `tenancy_reference_calibration.py`: the M365 tenancy posterior (DNS
  channel only) against Microsoft's endpoint attestation; GWS reported
  one-sided (the channel has no authoritative negative).
- `conformal_coverage.py`: distribution-free split-conformal coverage on
  the labelable nodes, with a deliberate falsifiability split showing the
  exchangeability boundary.

Private-run memo sequence:

```bash
python -m validation.run_calibration_bundle \
  --label "Aggregate Calibration Validation Memo"
```

By default the runner expects:

- `validation/corpus-private/by-vertical/*.txt` for per-stratum reference and
  tenancy calibration.
- `validation/corpus-private/consolidated.txt` for conformal coverage.
- `validation/runs-private/<UTC-stamp>/` for `reference.json`, `tenancy.json`,
  `conformal.json`, `memo.md`, and `meta.json`.

Use `--dry-run` to print the exact module invocations without network calls.
If you pass `--stamp`, it must be a single safe path segment: letters, digits,
dots, underscores, and hyphens only. The runner resolves the final run directory
under `--output-root` before writing artifacts. If `--output-root` is inside
this checkout, it must resolve under `validation/runs-private/`; operator-local
paths outside the checkout are allowed.
Before any network harness starts, the runner preflights the private corpus
inputs locally: the consolidated corpus must meet `--min-cell`, at least one
stratum file under `by-vertical/` must meet `--min-cell`, and dry runs print the
eligible and suppressed stratum counts. This catches empty, stale, or
unpublishable corpus layouts before spending operator time on a live run.
Review `memo.md` before copying any result into a committed validation memo.
The renderer is a backstop, not a substitute for review.

Committed memos from these network runs must follow
[docs/data-handling-policy.md](../docs/data-handling-policy.md): no apexes, no
organization names, no tenant IDs, no per-domain output, and no small cells.
Report only aggregate counts, rates, intervals, quantiles, and deltas. Suppress
or combine any stratum below 10 domains before committing the memo.

Public paper-number reproduction (no private corpus, no default network):

```bash
python -m validation.reproduce_paper_numbers
```

The default `paper` profile regenerates the public, no-private-data evidence
rows named in `docs/paper-outline.md`: suppression monotonicity, differential
verification, synthetic interval coverage, likelihood sensitivity, and layer
ablations. It writes `summary.md`, `manifest.json`, and per-harness outputs under
`validation/local/paper-numbers/<UTC-stamp>/`, which is gitignored. Use
`--profile smoke` to check the orchestrator quickly without waiting for full
paper-sized sweeps. If you pass `--stamp`, it follows the same single safe
path-segment rule as the calibration bundle runner.

## The fingerprint catalog audit

Run alongside live validation when changing fingerprint YAMLs:

```bash
python -m validation.audit_fingerprints \
  --markdown-output validation/live_runs/<UTC-stamp>/fingerprint_audit.md
```

The audit is no-network. It reports catalog metadata coverage and classifies
multi-detection fingerprints as `keep_any`, `review_for_all`, or
`tighten_patterns` so match-mode changes stay evidence-driven.

## Policy

Real apex domains never get committed here, not as corpus files and
not as artifacts. `CONTRIBUTING.md` codifies the same rule for the
rest of the repo. The .gitignore carves out `corpus-private/`,
`runs-private/`, `live_runs/`, and `local/` so users can curate without worrying
about accidentally leaking their list. `scripts/check_validation_hygiene.py`
runs in the local gate and release readiness to catch forced-added private paths
and target-domain fields in committed validation artifacts.

When you discover a generally-useful pattern (a real third-party SaaS
that any user would benefit from), open a PR adding the
`cname_target` rule to `recon_tool/data/fingerprints/surface.yaml`.
The pattern itself is generic; your corpus stays private.
