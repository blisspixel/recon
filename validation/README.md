# validation/

Local live-validation workspace. Only four files from this directory
are committed:

- `run_corpus.py` — the batch runner (no company names)
- `audit_fingerprints.py` — catalog audit runner (no company names)
- `corpus-example.txt` — fictional-company example showing the format
- `README.md` — this file

Everything else (`corpus-*.txt` lists of real apexes, `batch-*.json`
results, per-run output directories, summaries) stays local. See the
`/validation/*` block in `.gitignore` for the exact carve-out.

## Run

```bash
python validation/run_corpus.py --corpus validation/corpus-example.txt
# or, with a local real-company corpus:
python validation/run_corpus.py --corpus path/to/your-corpus.txt
```

Artifacts (`results.json`, `summary.json`, `summary.md`) land under
`validation/live_runs/<UTC-stamp>/` by default. Pass `--output-dir`
to override and `--compare-to <prior results.json>` to emit a headline
delta against an earlier run.

## Policy

Real apex domains never get committed here, not as corpus files and
not as artifacts. `CONTRIBUTING.md` codifies the same rule for the
rest of the repo.
