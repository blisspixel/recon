# recon → Elasticsearch / Kibana

Ingest recon `--json` output into Elasticsearch via an ingest
pipeline, surface the result in Kibana, and drive alerts via
Elastic's alerting framework. Field naming follows ECS (Elastic
Common Schema) where a sensible mapping exists; project-specific
fields stay under a `recon.*` namespace.

The example uses the shared input at
`examples/sample-output.json` (Northwind Traders, a Microsoft
fictional brand — see `examples/README.md`).

## Ingestion mechanics

Recommended flow:

1. Run `recon batch domains.txt --ndjson > /var/log/recon/lookups.ndjson`.
2. Filebeat (or Elastic Agent) tails the file and forwards each line
   as a JSON document.
3. Filebeat's pipeline configuration points at the ingest pipeline
   in `ingest-pipeline.json` below. The pipeline rewrites field names
   to the ECS-aligned shape and computes derived fields (severity,
   `event.category`).
4. The documents land in an index governed by `index-template.json`,
   which pins field types so Kibana visualizations and alert
   thresholds don't drift on first-write surprises.

A Filebeat input stanza for completeness:

```yaml
filebeat.inputs:
  - type: filestream
    paths: [/var/log/recon/*.ndjson]
    parsers:
      - ndjson:
          target: ""           # parse the whole line as the event
          add_error_key: true
    fields:
      pipeline: recon-lookup   # name matches the ingest-pipeline.json id
      data_stream:
        type: logs
        dataset: recon
```

## Field mapping

ECS-aligned fields land under standard ECS namespaces (`event.*`,
`host.*`, `organization.*`). recon's project-specific fields stay
under `recon.*` to avoid colliding with future ECS additions.

### Detection-pipeline fields (always present)

| recon JSON path | Elastic field | Use case |
|---|---|---|
| `queried_domain` | `host.domain` | Primary join key; standard ECS field |
| `display_name` | `organization.name` | Standard ECS organization namespace |
| `provider` | `recon.provider` | Filter to M365 vs Google Workspace |
| `confidence` | `recon.confidence` | Source field for `event.severity` derivation |
| `auth_type` | `recon.auth_type` | `Federated` vs `Managed` |
| `dmarc_policy` | `recon.email.dmarc_policy` | DMARC drift tracking |
| `email_security_score` | `recon.email.security_score` | 0–5 composite |
| `services` | `recon.services` | Shadow-IT alerting |
| `slugs` | `recon.slugs` | Keyword field for aggregations |
| `cloud_instance` | `recon.cloud_instance` | Sovereignty drift |
| `insights` | `recon.insights` | Pre-computed defensive narrative |

### Fusion-layer fields (present when `recon --fusion`)

| recon JSON path | Elastic field | Use case |
|---|---|---|
| `posterior_observations` | `recon.fusion.posteriors` | Object array — Bayesian per-claim |
| `posterior_observations[].sparse` | `recon.fusion.posteriors[].sparse` | Boolean keyword for "passive ceiling hit" |
| `evidence_conflicts` | `recon.fusion.conflicts` | Object array — cross-source disagreements |

## Severity mapping

The ingest pipeline derives `event.severity` (ECS-standard integer
0–7) from recon's `confidence`:

| recon `confidence` | `event.severity` | ECS label |
|---|---|---|
| `high` | 2 | informational |
| `medium` | 4 | low |
| `low` | 6 | medium |
| `partial` | 6 | medium |

This mapping is **deliberately inverted from intuition** for the
same reason documented in the Splunk README: high recon confidence
means strong public-signal evidence, which is *low*-severity from a
defender's view (the posture is well-characterized). Low recon
confidence on a hardened target is the higher-severity signal worth
operator review.

## Use cases

### Shadow-IT alerting

Kibana saved search (or Elastic alert rule):

```
recon.queried_domain : "northwindtraders.com"
AND NOT recon.slugs : "intune"
```

Replace with terms aggregation over a baseline set; Elastic
alerting can compare an aggregation against a baseline document.

### DMARC drift

Threshold alert on the index where, for the same `host.domain`,
the most-recent `recon.email.dmarc_policy` is weaker than the
previous one. Use Elasticsearch's `top_hits` aggregation grouped
by `host.domain` and order by `@timestamp` descending.

### Federation discovery

Tracking changes to `recon.auth_type` per `host.domain` — same
shape as the DMARC drift alert.

## Files in this directory

- `ingest-pipeline.json` — Elasticsearch ingest pipeline definition.
  PUT this to `_ingest/pipeline/recon-lookup` to activate.
- `index-template.json` — index template pinning field types for the
  `recon-lookup-*` indices.
- `expected-elastic-document.json` — the document Elasticsearch
  indexes after the pipeline runs against the shared
  `examples/sample-output.json` input. The CI test verifies this
  shape.

## Author of record

Maintainer-authored. **Vendor-unverified**: no Elastic employee
has QA'd this against a current Elastic Cloud / self-hosted ES
build. PRs welcome.
