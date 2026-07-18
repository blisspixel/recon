# Fingerprint PR

This is a public pull request. Provider and product names, provider-controlled
service domains, and provider-owned documentation are allowed. Do not include
evaluated-target names or domains, target-owned records, tenant identifiers,
screenshots, private corpus rows, or per-domain recon output.

## Service

**Name:**
**Slug:**
**Category file:** (e.g. `ai.yaml`, `security.yaml`, `infrastructure.yaml`)

## Validation

- [ ] `recon fingerprints check` exits 0 (no validation errors, no duplicate slugs)
- [ ] `recon fingerprints show <slug>` prints the new entry as expected
- [ ] `pytest tests/` passes locally
- [ ] The detection pattern is service-specific (not a generic substring)
- [ ] Tested with positive and negative reserved synthetic fixtures
- [ ] Any live-target validation stayed in a gitignored local workspace and is summarized only with disclosure-safe aggregates
- [ ] If the detection is probabilistic (e.g. common CNAME target), uses `match_mode: all` with a corroborating record
- [ ] This PR contains no evaluated-target identity, record, identifier, screenshot, corpus row, or per-domain output

## Disclosure-safe evidence

- **Provider-controlled reference:**
- **Generic provider record shape:**
- **Reserved positive fixture:**
- **Reserved negative fixture:**
- **Optional suppressed aggregate summary:**

Use `.invalid`, `.test`, or IETF example domains for fixtures. Replace
tenant-specific values with explicit placeholders. If a real identity is
load-bearing, use the private reporting path in `docs/data-handling-policy.md`
instead of including it here.

## Notes

Anything reviewers should know, including edge cases, related services, or false-positive scenarios you considered.
