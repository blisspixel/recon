# Contributing

Thanks for your interest in contributing to recon.

## Quick Start

```bash
git clone https://github.com/blisspixel/recon.git
cd recon
pip install -e ".[dev]"
pytest tests/
```

## Adding Fingerprints

The easiest way to contribute is adding new SaaS fingerprints. Edit `recon_tool/data/fingerprints.yaml`:

```yaml
- name: Service Name
  slug: service-slug          # lowercase, unique identifier
  category: Category Name     # use an existing category if possible
  confidence: high             # high, medium, or low
  detections:
    - type: txt                # txt, spf, mx, ns, cname, subdomain_txt, caa
      pattern: "^service-domain-verification="
      description: What this record means
```

Run `recon doctor` to validate your fingerprint loads correctly, then test against a domain you know uses the service.

## Code Changes

- Run `ruff check recon_tool/` and `pyright recon_tool/` before submitting.
- Run `pytest tests/` to verify nothing breaks.
- Integration tests (`pytest -m integration`) require network access and are skipped by default.

## Pull Requests

- Keep PRs focused — one feature or fix per PR.
- Fingerprint-only PRs are welcome and easy to review.
- Include a brief description of what you changed and why.
