# validation/

Live-validation workspace. The directory hosts the runners, the gap-analysis
tooling, and the fingerprint-discovery loop, plus a small fictional-example
corpus. Real-target corpora and per-domain outputs belong only in the ignored
private workspaces described below. Git ignore rules protect those paths, not a
real name copied into an arbitrary tracked file; see [Policy](#policy) below.

## What's in here

Committed (generic tooling, no company names):

- `run_corpus.py`: batch runner. Calls `recon` across a corpus file, emits
  `results.json`, `summary.json`, `summary.md` per run.
- `find_gaps.py`: reads a run (single file or directory of per-domain JSON)
  and surfaces unclassified CNAME terminal suffixes ranked by frequency. The
  first half of the fingerprint-discovery loop.
- `catalog_baseline.py`: reduces nested JSON or NDJSON opt-in typed DNS
  diagnostics into a
  private evidence queue, a private revision manifest, and a separate
  aggregate-only coverage report. It covers every bounded catalog record path
  and never writes a queried namespace into the aggregate report. Schema 1.1
  reports measured inputs separately from validation, timeout, and lookup
  errors.
- `triage_candidates.py`: programmatic filter on `gaps.json`: drops
  already-fingerprinted patterns, intra-org chains, and one-off noise. The
  output is the LLM-triage-ready candidate list.
- `diff_runs.py`: compares two run directories. Surfaces newly-attributed
  subdomains, lost slugs, and aggregate slug-frequency changes. Use after
  adding fingerprints to confirm uplift.
- `run_calibration_bundle.py`: maintainer-local wrapper around the reference,
  tenancy, and conformal re-split diagnostic harnesses. Captures aggregate JSON without
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
RECON emits opt-in JSON with count-only typed coverage and unmatched values
    ↓
PRIVATE REDUCER separates aggregate counts from evidence-bearing candidate rows
    ↓
PROGRAMMATIC FILTER drops same-zone, already-classified, and one-off noise
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
recon discover contoso.com \
    --output validation/local/contoso-candidates.json
```

`recon discover` performs the same lookup, bucketing, and existing-pattern and
same-zone filtering without leaving a raw result in the repository root. For a
real target, keep both the output path and any follow-up notes under
`validation/local/` or another ignored private workspace. Then hand the private
candidate file to the
[`/recon-fingerprint-triage`](../agents/claude-code/skills/recon-fingerprint-triage/SKILL.md)
skill, or to any agent reading the same input shape.

### Corpus run (deliberate, batch)

```bash
# Build (once) a private corpus
mkdir -p validation/corpus-private/
echo "contoso.com" > validation/corpus-private/saas-b2b.txt
# ... add more domains, organize as you like ...

# Run respectfully: concurrency 2 stays well under crt.sh's tolerance
python validation/run_corpus.py \
    --corpus validation/corpus-private/saas-b2b.txt \
    --concurrency 2 \
    --exclude-results validation/runs-private/<prior-run>/ \
    --limit 200

# Aggregate gaps across the run
python validation/find_gaps.py \
    --input validation/live_runs/<UTC-stamp>/ \
    --output validation/runs-private/<run>/gaps.json

# Filter to triage candidates
python validation/triage_candidates.py \
    --gaps validation/runs-private/<run>/gaps.json \
    --fingerprints src/recon_tool/data/fingerprints/ \
    --output validation/runs-private/<run>/candidates.json \
    --min-count 2 \
    --min-distinct-namespaces 2

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
    --round-kind baseline \
    --concurrency 4

# Next month: auto-diffs against the most recent prior scan
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --label monthly-2026-06 \
    --round-kind drift
```

Each run directory ends up with `results.ndjson` by default (`results.json`
with `--json-array`), `gaps.json`, `candidates.json`, `catalog-gaps.json`,
`catalog-aggregate.json`, `catalog-manifest.json`, `diff.json` (when comparing
to a prior run), and `meta.json`. The manifest and gap files remain private.
The aggregate file contains only counts, digests, revision metadata, and
environment details and must still be reviewed before any number is copied
into a committed memo. `meta.json` captures the scan timestamp, round kind,
label, raw input rows, normalized scheduled count, duplicate and malformed-row
counts, and candidate counts.
Reading `meta.json` from any run answers "when was this scanned, what was
found?" without re-running.

For large monthly cadence, keep `--no-ct` on unless CT coverage is the point and
use modest concurrency. Real-company corpora live entirely under
`validation/corpus-private/` and never leave your machine; only generic patterns
surfaced for triage become candidate PRs.
If `--output-root` is inside this checkout, it must resolve under one of the
gitignored private validation workspaces: `validation/runs-private/`,
`validation/live_runs/`, or `validation/local/`. Operator-local paths outside
the checkout are allowed.

Certificate-transparency corpus sessions are intentionally partial and
multi-session. Use streaming NDJSON plus a wall-clock cap so a session finalizes
aggregate artifacts instead of being killed by the terminal or CI wrapper:

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

`--exclude-results` may be repeated. It reads JSON arrays and streamed NDJSON,
including nested scan directories, canonicalizes and removes namespaces already
present in prior result files, then stores the filtered input manifest inside
the ignored output directory. Use it when private strata overlap so a pooled
round does not count the same queried namespace twice.
`--limit` applies after normalization, exclusion, and deduplication, making
fixed-size sequential rounds from a larger frozen private stratum reproducible.

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

The 2026-06-26 certificate-transparency sequence is closed and documented in
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
- `interval_coverage.py`: the v2.1.15 finite perturbation-containment gate for
  the 80% model-relative uncertainty band against selected likelihood scenarios.
  This is not empirical or Bayesian interval coverage. Memo:
  `interval-coverage.md`.
- `differential_verification.py`: variable elimination cross-checked
  against naive full-joint enumeration over the enumerable evidence sweep.
- `adversarial_properties.py`: the machine-checked local suppression property
  under fixed positive-factor assumptions (correlation.md section 3.4).
- `likelihood_sensitivity.py`: CAL8: posteriors/agreement under ±20%
  likelihood perturbation. Memo: `cal8-likelihood-sensitivity.md`.
- `drift_check.py`: the PV2 inference drift gate against
  `inference_baseline.json` (CI-gated).
- `layer_ablation.py`: what each layer adds: the Bayesian posterior vs
  slug-matching baselines (pooled and fired-regime), and Louvain vs
  connected components on planted partitions under bridging noise. Run
  and committed (fully synthetic): `layer-ablation.md`.
- `posture_distributions.py`: reads the engine's per-domain behavior as
  distributions: signed marginal entropy change bucketed by observable posture,
  and uncertainty-band width versus evidence. Pure aggregation unit-tested; the
  run is network/maintainer-local (aggregates only).

Reference-anchored / network (maintainer-local, aggregates only):

- `reference_calibration.py`: CAL3/CAL4: the email-policy posterior
  against the authoritative DMARC record, plus the held-out residual
  (the `dmarc_policy` unit masked, so predictor and label are disjoint).
  `--stratify-dir` for per-vertical cells. Memo:
  `reference-calibration.md`.
- `tenancy_reference_calibration.py`: the M365 tenancy posterior (DNS
  channel only) compared with Microsoft's endpoint attestation as corroboration;
  GWS reported one-sided (the channel has no authoritative negative).
- `conformal_coverage.py`: dependent conformal re-split diagnostics on the
  labelable email-policy score. Scorer-development disjointness is not
  established, so the current experiment makes no future-point coverage claim.
  Re-splits of one selected list report singleton, multi-label, and empty-set
  rates separately.

Private-run memo sequence:

```bash
python -m validation.run_calibration_bundle \
  --label "Aggregate Calibration Validation Memo"
```

By default the runner expects:

- `validation/corpus-private/by-vertical/*.txt` for per-stratum reference and
  tenancy calibration.
- `validation/corpus-private/consolidated.txt` for conformal re-split diagnostics.
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

The most recent recorded final public claim audit is the historical
`2026-06-29-scorecard-gate-claim-audit.md`. The most recent recorded local
submission-freeze proof is the historical
`2026-06-30-submission-freeze-local-proof.md`. They record passing checks for
the exact commits named in those memos, not the current tree. Later paper and
package changes leave the current draft unfrozen.
Before external submission packaging, follow
[docs/submission-freeze-checklist.md](../docs/submission-freeze-checklist.md)
to rerun the public proof commands, claim audit, and release gates while
preserving the same private-data and claim-boundary rules.

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
not as artifacts. Real organization names, tenant identifiers, target-owned
record values, and per-domain notes follow the same rule. `CONTRIBUTING.md`
codifies the same rule for the rest of the repo. The .gitignore carves out
`corpus-private/`,
`runs-private/`, `live_runs/`, and `local/` so users can curate without worrying
about accidentally leaking their list. `scripts/check_validation_hygiene.py`
runs in the local gate and release readiness to catch forced-added private paths
and target-domain fields in committed validation artifacts.

When you discover a generally-useful pattern (a real third-party SaaS
that any user would benefit from), open a PR adding the
`cname_target` rule to `src/recon_tool/data/fingerprints/surface.yaml`.
Provider names, provider-controlled pattern domains, and public provider
documentation are allowed because they define the generic catalog. The target
that exposed the pattern, its records, and its company details stay private.
