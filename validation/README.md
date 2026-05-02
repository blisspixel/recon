# validation/

Live-validation workspace. The directory hosts the runners, the gap-analysis
tooling, and the fingerprint-discovery loop, plus a small fictional-example
corpus. **Real company names are gitignored.** Curate your own private corpus
locally and the .gitignore keeps it out of commits — see [Policy](#policy)
below.

## What's in here

Committed (generic tooling, no company names):

- `run_corpus.py` — batch runner. Calls `recon` across a corpus file, emits
  `results.json`, `summary.json`, `summary.md` per run.
- `find_gaps.py` — reads a run (single file or directory of per-domain JSON)
  and surfaces unclassified CNAME terminal suffixes ranked by frequency. The
  first half of the fingerprint-discovery loop.
- `triage_candidates.py` — programmatic filter on `gaps.json`: drops
  already-fingerprinted patterns, intra-org chains, and one-off noise. The
  output is the LLM-triage-ready candidate list.
- `diff_runs.py` — compares two run directories. Surfaces newly-attributed
  subdomains, lost slugs, and aggregate slug-frequency changes. Use after
  adding fingerprints to confirm uplift.
- `audit_fingerprints.py` — no-network catalog audit. Reports metadata
  coverage and match-mode classification (`keep_any`, `review_for_all`,
  `tighten_patterns`).
- `corpus-example.txt` — fictional-company sample showing the format. Safe to
  commit because the names are made up.

Gitignored (your private workspace):

- `corpus-private/` — your curated test bed of real apexes, organized however
  you want (by region, vertical, customer type)
- `runs-private/` — output dirs from each run (results, gaps, diffs)
- `local/` — any other scratch space (notes, half-finished YAMLs, etc.)

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
recon stripe.com --json --include-unclassified > result.json
python validation/find_gaps.py --input result.json --output gaps.json
python validation/triage_candidates.py \
    --gaps gaps.json --fingerprints recon_tool/data/fingerprints/ \
    --output candidates.json
```

Then hand `candidates.json` to the
[`/recon-fingerprint-triage`](../claude-code/skills/recon-fingerprint-triage/SKILL.md)
Claude Code skill, or to any agent reading the same input shape.

### Corpus run (deliberate, batch)

```bash
# Build (once) a private corpus
mkdir -p validation/corpus-private/
echo "stripe.com" > validation/corpus-private/saas-b2b.txt
# ... add more domains, organize as you like ...

# Run respectfully — concurrency 2 stays well under crt.sh's tolerance
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

- `--no-ct` — skip cert-transparency providers entirely. Discovery falls back
  to common-subdomain probes + apex CNAME walks. Use for runs of 1000+ domains
  where you want zero load on public CT services.
- `--concurrency N` (on `run_corpus.py`) — how many `recon` invocations run in
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

# Next month — auto-diffs against the most recent prior scan
python validation/scan.py \
    --corpus validation/corpus-private/consolidated.txt \
    --label monthly-2026-06
```

Each run directory ends up with `results.json`, `gaps.json`,
`candidates.json`, `diff.json` (when comparing to a prior run), and
`meta.json` capturing the scan timestamp, label, corpus size, and
candidate counts. Reading `meta.json` from any run answers "when was
this scanned, what was found?" without re-running.

For 2500-domain monthly cadence: ~30-50 minutes wall-clock at
`--concurrency 4` with `--no-ct` (the `scan.py` default). Real-company
corpora live entirely under `validation/corpus-private/` and never leave
your machine; only the generic patterns surfaced for triage become
candidate PRs.

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
`runs-private/`, and `local/` so users can curate without worrying about
accidentally leaking their list.

When you discover a generally-useful pattern (a real third-party SaaS
that any user would benefit from), open a PR adding the
`cname_target` rule to `recon_tool/data/fingerprints/surface.yaml`.
The pattern itself is generic; your corpus stays private.
