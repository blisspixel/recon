# recon → Elasticsearch / Kibana

Ingest recon `--json` output into Elasticsearch via an ingest
pipeline, surface the result in Kibana, and drive alerts via
Elastic's alerting framework. Field naming follows ECS (Elastic
Common Schema) where a sensible mapping exists; project-specific
fields stay under a `recon.*` namespace.

The example uses the reserved synthetic input at
`examples/sample-output.json`; see `examples/README.md` for the disclosure
boundary.

## Ingestion mechanics

Recommended flow:

1. Run `recon batch domains.txt --ndjson --no-fusion > /var/log/recon/lookups.ndjson`.
2. Filebeat (or Elastic Agent) tails the file and forwards each line
   as a JSON document.
3. Filebeat selects the `recon-lookup` ingest pipeline and a
   `recon-lookup-*` index. The pipeline rewrites field names to the
   ECS-aligned shape and adds event classification fields. It does not derive
   severity from recon confidence.
4. The documents land in an index governed by `index-template.json`,
   which pins the documented field types so Kibana visualizations and alert
   thresholds don't drift on first-write surprises.

A Filebeat input stanza for completeness:

```yaml
filebeat.inputs:
  - type: filestream
    id: recon-lookups
    paths: [/var/log/recon/*.ndjson]
    parsers:
      - ndjson:
          target: ""           # parse the whole line as the event
          add_error_key: true
    index: "recon-lookup-%{+yyyy.MM}"
    pipeline: recon-lookup
```

The custom index name matches `index-template.json`; the explicit pipeline
selection matches the pipeline installed from `ingest-pipeline.json`. The
template also declares `recon-lookup` as its default pipeline, so events sent
directly to a matching index receive the same transformation. Install both
artifacts before starting the input.

## Field mapping

ECS-aligned fields land under standard ECS namespaces (`event.*`,
`host.*`). recon's project-specific fields stay under `recon.*` to avoid
colliding with future ECS additions. In particular, `display_name` remains a
recon field because public identity metadata is not a verified legal
organization name.

### Detection-pipeline fields (always present)

| recon JSON path | Elastic field | Use case |
|---|---|---|
| `queried_domain` | `host.domain` | Primary join key; standard ECS field |
| `display_name` | `recon.display_name` | Public identity display label; not a verified legal organization name |
| `provider` | `recon.provider` | Filter to M365 vs Google Workspace |
| `confidence` | `recon.confidence` | Overall evidential support; not alert severity |
| `auth_type` | `recon.auth_type` | `Federated` vs `Managed` |
| `dmarc_policy` | `recon.email.dmarc_policy` | DMARC drift tracking |
| `email_security_score` | `recon.email.security_score` | Count of five apex-observable controls; not an overall security score |
| `services` | `recon.services` | Review changes in public service indicators |
| `slugs` | `recon.slugs` | Keyword field for aggregations |
| `cloud_instance` | `recon.cloud_instance` | Sovereignty drift |
| `insights` | `recon.insights` | Hedged observation text derived from retained evidence |

### Fusion-layer fields (always present; populated only when fusion is enabled)

| recon JSON path | Elastic field | Use case |
|---|---|---|
| `posterior_observations` | `recon.fusion.posteriors` | Object array containing Bayesian per-claim output |
| `posterior_observations[].sparse` | `recon.fusion.posteriors[].sparse` | Marks that the evidence-responsive display mass is at its configured floor |

`posterior_observations` remains present as an empty array when fusion is
disabled, including in the shared `--no-fusion` sample.

### Cross-source diagnostics (always present; independent of fusion)

| recon JSON path | Elastic field | Use case |
|---|---|---|
| `evidence_conflicts` | `recon.evidence_conflicts` | Object array containing a field name and its disagreeing `{value, source, confidence}` candidates |

`evidence_conflicts` can be populated whether fusion is enabled or disabled.

## Confidence and alert priority

Do not derive `event.severity` from `confidence`, `evidence_confidence`, or
`inference_confidence`. Those fields describe evidential support inside
recon's public-observation model. `partial` is a separate boolean that reports
collection completeness. Elastic rule severity should come from explicit
operator policy, such as an unexpected persistent change on a critical domain.

## Use cases

### Public fingerprint indicator review

Kibana saved search (or Elastic alert rule):

```
host.domain : "gamma.invalid"
AND NOT recon.slugs : "intune"
```

Replace with terms aggregation over a baseline set; Elastic
alerting can compare an aggregation against a baseline document. A newly
observed slug means the public fingerprint set changed. It does not establish
active use, ownership, approval status, or an unsanctioned deployment.

### DMARC drift

Threshold alert on the index where, for the same `host.domain`,
the most-recent `recon.email.dmarc_policy` is weaker than the
previous one. Use Elasticsearch's `top_hits` aggregation grouped
by `host.domain` and order by `@timestamp` descending.

### Federation discovery

Tracking changes to `recon.auth_type` per `host.domain` uses the same
shape as the DMARC drift alert. The result is an observed metadata change, not
an explanation of its cause.

## Files in this directory

- `ingest-pipeline.json`  -  Elasticsearch ingest pipeline definition.
  PUT this to `_ingest/pipeline/recon-lookup` to activate.
- `index-template.json`  -  index template pinning field types for the
  `recon-lookup-*` indices.
- `expected-elastic-document.json`  -  representative mapped fields and
  selected pass-through fields after the pipeline runs against the shared
  `examples/sample-output.json` input. Actual Filebeat events also carry
  agent metadata and all unmapped recon fields. CI verifies the documented
  contract subset.

## Verification status

**Vendor-unverified**: no Elastic employee has QA'd this against a current
Elastic Cloud / self-hosted Elasticsearch build. PRs welcome.
