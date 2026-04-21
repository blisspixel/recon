# Fingerprint PR

## Service

**Name:**
**Slug:**
**Category file:** (e.g. `ai.yaml`, `security.yaml`, `infrastructure.yaml`)

## Validation

- [ ] `recon fingerprints check` exits 0 (no validation errors, no duplicate slugs)
- [ ] `recon fingerprints show <slug>` prints the new entry as expected
- [ ] `pytest tests/` passes locally
- [ ] The detection pattern is service-specific (not a generic substring)
- [ ] Tested against at least one public domain known to use this service
- [ ] If the detection is probabilistic (e.g. common CNAME target), uses `match_mode: all` with a corroborating record

## Test domain

`example.com` — expected to match after this PR.

Run:

```bash
uv run recon example.com --json | jq '.slugs'
```

Expected to include `"<slug>"`.

## Notes

Anything reviewers should know — edge cases, related services, false-positive scenarios you considered.
