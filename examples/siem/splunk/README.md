# recon → Splunk

Ingest recon `--json` output into Splunk, extract structured fields,
review public-namespace observations, and optionally drive operator-defined
alerts. The example uses the reserved synthetic input at
`examples/sample-output.json`; see `examples/README.md` for the disclosure
boundary.

## Ingestion mechanics

Recommended flow:

1. Pipe `recon batch domains.txt --ndjson --no-fusion` into a file under your
   Splunk universal forwarder's monitored path.
2. The forwarder sends each line to the Splunk parsing tier. Deploy
   `props.conf` on the component that performs parsing in your topology so
   Splunk indexes the JSON fields.
3. Saved searches in `savedsearches.conf` (below) drive scheduled
   alerts.

No custom Python or modular input is required. recon's `--ndjson` emits one
JSON document per line, a shape Splunk's `INDEXED_EXTRACTIONS=json` can ingest
natively. This worked fixture explicitly uses `--no-fusion`; fusion fields
remain in the stable JSON shape but their arrays are empty.

## Field mapping

Splunk's default JSON ingestion auto-extracts every top-level
recon field into a Splunk event field of the same name. The
following are the mappings most defenders need to know: the
columns name a recon JSON path, the Splunk field it lands in,
and the use case that field supports.

### Detection-pipeline fields (always present)

| recon JSON path | Splunk field | Use case |
|---|---|---|
| `queried_domain` | `queried_domain` | Primary key for joins and alerts on a queried public namespace |
| `display_name` | `display_name` | Display label returned by public identity metadata; not a verified legal organization name |
| `provider` | `provider` | Filter to M365 vs Google Workspace vs other |
| `confidence` | `confidence` | Overall evidential support; not alert severity |
| `auth_type` | `auth_type` | Observed `Federated` vs `Managed` identity metadata |
| `dmarc_policy` | `dmarc_policy` | Track DMARC enforcement drift (`reject` → `quarantine` regressions) |
| `email_security_score` | `email_security_score` | Count of five apex-observable email controls; not an overall security score |
| `services` | `services{}` (mv field) | Review changes in public service indicators |
| `slugs` | `slugs{}` (mv field) | Machine-readable counterpart of `services` |
| `cloud_instance` | `cloud_instance` | Sovereignty drift (`microsoftonline.com` vs `.us`) |
| `insights` | `insights{}` (mv field) | Hedged observation text derived from retained evidence |

### Fusion-layer fields (always present; populated only when fusion is enabled)

| recon JSON path | Splunk field | Use case |
|---|---|---|
| `posterior_observations{}.name` | `posterior_observations{}.name` | Per-claim Bayesian posterior label |
| `posterior_observations{}.posterior` | `posterior_observations{}.posterior` | Model-relative support for the claim under the committed network |
| `posterior_observations{}.sparse` | `posterior_observations{}.sparse` | True when effective display mass is at its configured floor |

`posterior_observations` is part of every successful lookup object. It is an
empty array when fusion is disabled, including in the shared sample.

### Cross-source diagnostics (always present; independent of fusion)

| recon JSON path | Splunk field | Use case |
|---|---|---|
| `evidence_conflicts{}.field` | `evidence_conflicts{}.field` | Which TenantInfo field had cross-source disagreement |

`evidence_conflicts` is also part of every successful lookup object. It can be
populated whether fusion is enabled or disabled.

## Confidence and alert priority

Do not derive Splunk severity from `confidence`, `evidence_confidence`, or
`inference_confidence`. Those fields describe evidential support inside
recon's public-observation model. `partial` is a separate boolean that reports
collection completeness. Alert priority should instead come from explicit
operator policy, such as an unexpected change on a monitored domain, the
criticality of that domain, and the persistence of the observation.

## Use cases

### Public fingerprint indicator review

Search: any new `services[]` entry that wasn't present in the prior
lookup of the same `queried_domain`. The `slugs[]` array is the
machine-readable join key. A newly observed slug means the public fingerprint
set changed. It does not establish active use, ownership, approval status, or
an unsanctioned deployment.

```spl
index=recon sourcetype=recon:lookup
| stats values(slugs) as current_slugs by queried_domain
| lookup recon_slug_baseline.csv queried_domain OUTPUT slugs AS baseline_slugs
| eval new_slugs=mvfilter(NOT in(current_slugs, baseline_slugs))
| where mvcount(new_slugs) > 0
| table queried_domain new_slugs
```

> **Why `in(x, mv_field)` and not `match(x, "regex")`?** A previous
> version of this example used
> `match(current_slugs, mvjoin(baseline_slugs, "|"))`, which
> interprets baseline slug values as a regex alternation. A
> baseline slug containing regex metacharacters such as `.*`
> would match any `current_slug` and silently suppress the alert.
> `in()` inside `mvfilter()` compares literal values element by
> element, with no regex semantics, and is the right primitive for
> set-membership tests against arbitrary identifier strings.

### DMARC drift

Search: a `dmarc_policy` weakening (`reject` → `quarantine` →
`none`) on the same queried domain across lookups.

```spl
index=recon sourcetype=recon:lookup queried_domain="gamma.invalid"
| sort _time
| streamstats current=f last(dmarc_policy) as prev_policy by queried_domain
| where (prev_policy="reject" AND dmarc_policy!="reject") OR (prev_policy="quarantine" AND dmarc_policy="none")
| table _time queried_domain prev_policy dmarc_policy
```

### Federation discovery

Search: a queried domain's observed authentication type changes from
`Managed` to `Federated` or the reverse. This is a change in public identity
metadata worth operator review; recon does not establish the cause.

```spl
index=recon sourcetype=recon:lookup
| streamstats current=f last(auth_type) as prev_auth_type by queried_domain
| where prev_auth_type!=auth_type
| table _time queried_domain prev_auth_type auth_type
```

## Files in this directory

- `props.conf`  -  Splunk sourcetype definition. Drop into
  `$SPLUNK_HOME/etc/system/local/` (or `apps/<your-app>/local/`).
- `savedsearches.conf`  -  three example saved searches matching the
  use cases above. Adjust schedules and `actions` to taste.
- `expected-splunk-event.json`  -  what a Splunk event looks like
  after `props.conf` extraction, given the
  `examples/sample-output.json` input. This is the contract the CI
  test verifies.

## Verification status

**Vendor-unverified**: no Splunk employee has QA'd this against a current
Splunk Cloud / Splunk Enterprise build.
A PR from a Splunk customer / employee that fixes any conf-file
syntax drift is welcome.
