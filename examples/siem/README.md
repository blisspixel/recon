# recon → SIEM consumption examples

End-to-end mappings from recon's `--json` / `--ndjson` output to two
common SIEM ingestion paths. Each example carries:

- A field-by-field mapping table (recon JSON path → SIEM field).
- A worked example: the same reserved synthetic
  `examples/sample-output.json` fixture parsed and reshaped into the SIEM's
  native event shape.
- A copy-pasteable parser snippet (Splunk `props.conf`, Elasticsearch
  ingest pipeline).

The examples preserve recon's semantics: `confidence`,
`evidence_confidence`, and `inference_confidence` describe evidential support,
not risk, impact, urgency, or alert severity. Operators can add their own
severity policy from changes and conditions relevant to their environment.

These examples are **vendor-unverified**. A SIEM-vendor employee opening a PR
to validate or extend the mapping is welcome.

## Why publish these

recon's `--json` shape is the stable v2.0 contract. These examples show how
that contract can be represented in two common SIEM event shapes. The CI gate
in `tests/test_siem_examples.py` re-parses each fixture, checks documented
input paths, and verifies selected canonical mappings on every push. It does
not run Splunk or Elasticsearch, validate vendor configuration, or execute the
example searches.

## What's covered today

| SIEM | Example | Use cases shown |
|---|---|---|
| Splunk | `splunk/` | Public fingerprint indicator review, DMARC drift, federation discovery |
| Elasticsearch / Kibana | `elastic/` | Same set, ECS-aligned where the semantics match |

Both examples consume the same explicitly non-fused input
(`examples/sample-output.json`, modeled on `recon --json --no-fusion`) and
produce the same logical observation event;
they differ only in the ingest mechanics and field-naming
conventions.

## What's not covered

- ArcSight, QRadar, Sumo Logic, Microsoft Sentinel KQL queries.
  Welcome as community PRs. The Splunk and Elastic mappings are the
  current quality-bar floor; more validated mappings would raise the bar.
- Real-time streaming ingestion. The examples assume batch ingest
  of `recon --json` output (file drop, beats input, log file).
  Real-time would require recon to expose an HTTP push surface,
  which is not on the roadmap (see "Intentionally Out Of Scope" in
  `docs/roadmap.md`).
- Per-alert tuning. The use-case framing names *which fields* to
  watch; the actual alerting threshold (number or type of new public
  fingerprint indicators, frequency of DMARC drift to ignore) is operator
  policy and intentionally not encoded here. Confidence must not be treated as
  severity.

## How to extend

Each subdirectory carries its own README with the SIEM-specific
ingestion details. The shape of a new mapping should be:

1. **Use-case framing.** Which defensive question does this enable?
2. **Field mapping table.** Recon JSON path → SIEM field. Per
   detection-pipeline field AND per fusion-layer field if
   applicable.
3. **Interpretation semantics.** Preserve the distinction between evidence
   support, collection completeness, observed configuration, and
   operator-defined alert priority.
4. **Worked example.** Input from `examples/sample-output.json`,
   expected SIEM event after ingestion. Verifiable by `pytest
   tests/test_siem_examples.py`.
5. **Verification status.** State whether a current SIEM release has been
   exercised, and keep vendor-unverified examples labeled as such.

## Tested

CI (`tests/test_siem_examples.py`) verifies:

- The shared worked input and each expected-output file parse as JSON.
- Every recon JSON path referenced in each mapping table is reachable
  in the input.
- Selected mapped fields in each expected event match the canonical input.
- Neither worked event invents severity from recon confidence.

The tests are static contract checks. A future regression such as a renamed
schema field fails locally and in CI, but live ingestion and saved-search
semantics still require validation in the target SIEM.
