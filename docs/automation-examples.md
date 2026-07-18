# Automation Examples

This page is for scripts that consume recon JSON. It complements
[`schema.md`](schema.md) and [`recon-schema.json`](recon-schema.json); it does
not define a new contract.

Use these rules before parsing:

1. Check the process exit code first. `0` means output is parseable. For batch
   modes it does not mean every domain succeeded. `2` and `3` produce no JSON.
2. Do not parse the Rich panel or Markdown output. Use `--json`, `--ndjson`, or
   MCP `structuredContent`.
3. Ignore unknown JSON fields. Additive fields are non-breaking in the 2.x
   contract.

## Single Lookup

`recon <domain> --json` emits one lookup object on success. Validate it against
the root of [`recon-schema.json`](recon-schema.json). The committed fictional
sample is [`../examples/sample-output.json`](../examples/sample-output.json).

```python
import json
from pathlib import Path

payload = json.loads(Path("examples/sample-output.json").read_text())
assert payload["record_type"] == "lookup"
assert payload["schema_version"] == "2.0"
```

## Batch Array

`recon batch domains.txt --json` emits a bare array. Each element is either a
lookup object or a closed `BatchErrorRecord`.

A valid batch invocation retains exit 0 for mixed-error and all-error output.
Inspect every record. `error_kind` is derived from structured control flow, not
display-message keywords. Unexpected internal details are replaced with stable
text; use reviewed local debug logs when diagnosis requires the full exception.

```python
import json
from pathlib import Path

schema = json.loads(Path("docs/recon-schema.json").read_text())
required_lookup_fields = set(schema["required"])
error_fields = {"domain", "error", "error_kind", "record_type"}


def classify_batch_record(record: dict[str, object]) -> str:
    if record.get("record_type") == "error" and set(record) == error_fields:
        return "error"
    if required_lookup_fields <= set(record):
        return "lookup"
    return "unknown"
```

Reject `unknown`. A malformed record is a contract break or a partial write, not
an incomplete finding.

## Batch Wrapper

`recon batch domains.txt --json --include-ecosystem` emits a `BatchResult`
wrapper:

```json
{
  "record_type": "batch_result",
  "domains": [
    {
      "domain": "not a domain",
      "error": "invalid domain syntax",
      "error_kind": "validation",
      "record_type": "error"
    }
  ],
  "ecosystem_hyperedges": []
}
```

Parse each `domains[]` element with the same classifier as the bare batch array.
The wrapper remains a wrapper even when every domain failed, so automation can
always branch on `record_type == "batch_result"`.

## NDJSON

`recon batch domains.txt --ndjson` emits one JSON object per line. Parse and
classify each line independently:

```python
for line in stream:
    if not line.strip():
        continue
    record = json.loads(line)
    kind = classify_batch_record(record)
    if kind == "unknown":
        raise ValueError(f"malformed recon record: {record!r}")
```

NDJSON is the safest mode for long batches because each line can be processed as
soon as it arrives.

## Delta

`recon delta <domain>` and `recon <domain> --compare snapshot.json` emit a
`DeltaReport`. Validate it against `$defs/DeltaReport`.

```json
{
  "record_type": "delta",
  "domain": "contoso.com",
  "added_services": ["MTA-STS"],
  "removed_services": [],
  "added_slugs": [],
  "removed_slugs": [],
  "added_signals": [],
  "removed_signals": [],
  "changed_auth_type": null,
  "changed_dmarc_policy": {"from": "none", "to": "reject"},
  "changed_email_security_score": {"from": 2, "to": 4},
  "changed_confidence": null,
  "changed_domain_count": null
}
```

Report the fields as deltas only. Do not narrate causes unless another source
provided that explanation.

## Cohort Summary

`recon batch domains.txt --summary --json` emits the compatible aggregate-only
2.1 contract. Use
`recon batch domains.txt --summary --summary-schema 2.2 --json` for the opt-in
contract with raw-evidence-bound DMARC rates and corrected missingness. Both use
`record_type == "cohort_summary"`; route on the exact `schema_version`. They are
documented in [`aggregate-state.md`](aggregate-state.md), not in the v2.0
single-domain schema root. Treat suppressed cells as intentionally absent
detail, not as zero.
