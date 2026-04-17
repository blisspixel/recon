# Contributing

Thanks for your interest in contributing to recon.

## Quick Start

```bash
git clone https://github.com/blisspixel/recon.git
cd recon
uv sync --extra dev                    # or: pip install -e ".[dev]"
pre-commit install                     # activate pre-commit hooks
uv run pytest tests/                   # or: pytest tests/
```

## Adding Fingerprints

The easiest way to contribute is adding new SaaS fingerprints. Edit `recon_tool/data/fingerprints.yaml`:

```yaml
- name: Service Name
  slug: service-slug          # lowercase, unique identifier
  category: Category Name     # use an existing category if possible
  confidence: high             # high, medium, or low
  detections:
    - type: txt                # txt, spf, mx, ns, cname, subdomain_txt, caa, srv, dmarc_rua
      pattern: "^service-domain-verification="
      description: What this record means
```

### Validate locally before opening a PR

```bash
uv run python scripts/validate_fingerprint.py recon_tool/data/fingerprints.yaml
```

The script runs the same validation recon uses at runtime — regex safety (ReDoS heuristic), required fields, known detection types, weight range (0.0–1.0), `match_mode` value. Exits 0 on success, 1 on failure with per-entry error messages.

### Chained patterns (`match_mode: all`)

For high-confidence attribution where a single record could be a false positive, use `match_mode: all` — the fingerprint only fires when every listed detection matches. See [docs/fingerprints.md](docs/fingerprints.md#chained-patterns-match_mode-all) for details.

### Fingerprint PR checklist

- The fingerprint validates locally with `scripts/validate_fingerprint.py`
- At least one detection pattern uses a service-specific token (not a generic substring)
- You've tested it against a real domain you know uses the service (add it as an integration-test fixture if possible)
- You've run `pytest tests/` — property tests must still pass on the sparse-data corpus

Custom fingerprints live in `~/.recon/fingerprints.yaml` and are **additive only** — they cannot override built-ins. Run `recon doctor` to confirm the tool loads your custom file.

## Adding Signals

Custom signal rules go in `~/.recon/signals.yaml`:

```yaml
signals:
  - name: My Custom Signal
    category: Custom
    confidence: medium
    description: What this signal means
    requires:
      any: [slug-a, slug-b, slug-c]    # fingerprint slugs to match
    min_matches: 2                       # how many must be present
```

## Code Changes

- Run `pre-commit run --all-files` or `ruff check recon_tool/` and `pyright recon_tool/` before submitting.
- Run `pytest tests/` to verify nothing breaks. Coverage must stay above 80%.
- Integration tests (`pytest -m integration`) require network access and are skipped by default.

## Pull Requests

- Keep PRs focused — one feature or fix per PR.
- Fingerprint-only PRs are welcome and easy to review.
- Include a brief description of what you changed and why.
