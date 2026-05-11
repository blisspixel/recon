# recon → SIEM consumption examples

End-to-end mappings from recon's `--json` / `--ndjson` output to two
common SIEM ingestion paths. Each example carries:

- A field-by-field mapping table (recon JSON path → SIEM field).
- A worked example: the same `examples/sample-output.json` (Northwind
  Traders, a Microsoft fictional brand) parsed and reshaped into the
  SIEM's native event shape.
- A copy-pasteable parser snippet (Splunk `props.conf`, Elasticsearch
  ingest pipeline).
- Severity / criticality mapping that derives an alert priority from
  recon's `confidence` + `inference_confidence` fields.

These are **maintainer-authored, vendor-unverified**. A SIEM-vendor
employee opening a PR to validate or extend the mapping is welcome.

## Why publish these

recon's `--json` shape is the schema lock target for v2.0 (see
`docs/roadmap.md`). Locking a contract no published example
demonstrates is premature: an example that actually parses and
ingests is the load-bearing evidence that the contract is usable.
The CI gate in `tests/test_siem_examples.py` re-parses each worked
example on every push, so a future schema change that breaks SIEM
ingestion fails the test before it can reach a release tag.

## What's covered today

| SIEM | Example | Severity mapping | Use cases shown |
|---|---|---|---|
| Splunk | `splunk/` | recon `confidence` → Splunk `severity` field | Shadow-IT alerting, DMARC drift, federation discovery |
| Elasticsearch / Kibana | `elastic/` | recon `confidence` → ECS `event.severity` | Same set, ECS-shaped |

Both examples consume the same input
(`examples/sample-output.json`) and produce the same logical event;
they differ only in the ingest mechanics and field-naming
conventions.

## What's not covered

- ArcSight, QRadar, Sumo Logic, Microsoft Sentinel KQL queries.
  Welcome as community PRs. The Splunk and Elastic mappings are the
  v1.9.x quality-bar floor (two SIEMs); more raises the bar.
- Real-time streaming ingestion. The examples assume batch ingest
  of `recon --json` output (file drop, beats input, log file).
  Real-time would require recon to expose an HTTP push surface,
  which is not on the roadmap (see "Intentionally Out Of Scope" in
  `docs/roadmap.md`).
- Per-alert tuning. The use-case framing names *which fields* to
  watch; the actual alerting threshold (number of new shadow-IT
  apps to fire on, frequency of DMARC drift to ignore) is operator
  policy and intentionally not encoded here.

## How to extend

Each subdirectory carries its own README with the SIEM-specific
ingestion details. The shape of a new mapping should be:

1. **Use-case framing.** Which defensive question does this enable?
2. **Field mapping table.** Recon JSON path → SIEM field. Per
   detection-pipeline field AND per fusion-layer field if
   applicable.
3. **Severity mapping.** Documented mapping from recon's
   `confidence` / `inference_confidence` to the SIEM's native
   priority.
4. **Worked example.** Input from `examples/sample-output.json`,
   expected SIEM event after ingestion. Verifiable by `pytest
   tests/test_siem_examples.py`.
5. **Author of record.** Maintainer-authored unless a SIEM-vendor
   employee verified it.

## Tested

CI (`tests/test_siem_examples.py`) verifies:

- The worked input file parses as JSON and matches `examples/sample-output.json`.
- Every recon JSON path referenced in each mapping table is reachable
  in the input.
- Each expected-output file parses as JSON.
- The severity-mapping documented in each README is consistent with
  what the worked output shows.

A future regression that breaks the mapping (e.g., a renamed schema
field) fails the test before the schema change can reach a tag.
