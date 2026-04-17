---
name: Bug report
about: Something recon got wrong, crashed on, or behaved unexpectedly
title: "[Bug] "
labels: bug
---

## What happened

Clear, concrete description of the observed behavior.

## What should have happened

What did you expect instead?

## Reproduction

The minimum command sequence to reproduce.

```bash
recon example.com
recon example.com --json --explain
```

## Environment

- recon version: (output of `recon --version`)
- Python version: (output of `python --version`)
- OS: (Windows 11 / macOS 14 / Ubuntu 22.04 / etc.)
- Install method: `pip install recon-tool`, `pip install -e .`, `uv sync`, etc.

## Output

**IMPORTANT:** For wrong-output bugs (provider misclassified, insight
wording wrong, service miscategorized), paste the full `--json --explain`
output. The evidence DAG is the authoritative answer to "why did recon
say that."

```
# paste the output of:
# recon example.com --json --explain
```

If the bug is a crash, paste the full stack trace.

## Additional context

- Does `recon doctor` show any degraded sources?
- Is the domain heavily proxied / behind a CDN / minimal-DNS?
- Does the bug reproduce on a different domain with similar
  characteristics?
