# recon → Splunk

Ingest recon `--json` output into Splunk, extract structured fields,
and surface defensive findings as alerts. The example uses the shared
input at `examples/sample-output.json` (Northwind Traders, a
Microsoft fictional brand — see `examples/README.md`).

## Ingestion mechanics

Recommended flow:

1. Pipe `recon batch domains.txt --ndjson` into a file under your
   Splunk universal forwarder's monitored path.
2. Splunk applies `props.conf` (below) to auto-extract JSON fields
   into Splunk-native event fields.
3. Saved searches in `savedsearches.conf` (below) drive scheduled
   alerts.

No custom Python or modular input is required. recon's `--ndjson`
emits one JSON document per line — a shape Splunk's `INDEXED_EXTRACTIONS=json`
ingests natively.

## Field mapping

Splunk's default JSON ingestion auto-extracts every top-level
recon field into a Splunk event field of the same name. The
following are the mappings most defenders need to know — the
columns name a recon JSON path, the Splunk field it lands in,
and the use case that field supports.

### Detection-pipeline fields (always present)

| recon JSON path | Splunk field | Use case |
|---|---|---|
| `queried_domain` | `queried_domain` | Primary key for joins / alerts on a specific tenant |
| `display_name` | `display_name` | Human-readable tenant label in dashboards |
| `provider` | `provider` | Filter to M365 vs Google Workspace vs other |
| `confidence` | `confidence` | Drives severity mapping (see below) |
| `auth_type` | `auth_type` | `Federated` vs `Managed` — federation discovery |
| `dmarc_policy` | `dmarc_policy` | Track DMARC enforcement drift (`reject` → `quarantine` regressions) |
| `email_security_score` | `email_security_score` | 0–5 composite score for trend dashboards |
| `services` | `services{}` (mv field) | Shadow-IT alerting — fire on new entries |
| `slugs` | `slugs{}` (mv field) | Machine-readable counterpart of `services` |
| `cloud_instance` | `cloud_instance` | Sovereignty drift (`microsoftonline.com` vs `.us`) |
| `insights` | `insights{}` (mv field) | Pre-computed defensive narrative |

### Fusion-layer fields (present when `recon --fusion`)

| recon JSON path | Splunk field | Use case |
|---|---|---|
| `posterior_observations{}.name` | `posterior_observations{}.name` | Per-claim Bayesian posterior label |
| `posterior_observations{}.posterior` | `posterior_observations{}.posterior` | Calibrated probability for the claim |
| `posterior_observations{}.sparse` | `posterior_observations{}.sparse` | True when interval is wide (hardened target) |
| `evidence_conflicts{}.field` | `evidence_conflicts{}.field` | Which TenantInfo field had cross-source disagreement |

## Severity mapping

recon's `confidence` and `inference_confidence` fields drive Splunk's
`severity` alert priority:

| recon `confidence` | Splunk `severity` | Splunk numeric |
|---|---|---|
| `high` | `informational` (or `notice` for new tenants) | 1 |
| `medium` | `low` | 2 |
| `low` | `medium` | 3 |
| `partial` (incomplete) | `medium` | 3 |

This mapping is deliberately **inverted from intuition**: a *high*
recon confidence means we observed strong public-signal evidence,
which is a *low*-severity alert because the operator's defensive
posture is well-characterized. A *low* confidence on a hardened
target is the higher-severity signal — it tells the operator their
hardening is working, and unusual new shadow-IT entries appearing
under low confidence deserve more scrutiny.

The mapping is intentionally documented as policy, not derived
from a Splunk-only convention: SIEM operators tune this for their
context.

## Use cases

### Shadow-IT alerting

Search: any new `services[]` entry that wasn't present in the prior
lookup of the same `queried_domain`. The `slugs[]` array is the
machine-readable join key.

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
> element — no regex semantics — and is the right primitive for
> set-membership tests against arbitrary identifier strings.

### DMARC drift

Search: a `dmarc_policy` weakening (`reject` → `quarantine` →
`none`) on the same tenant across lookups.

```spl
index=recon sourcetype=recon:lookup queried_domain="northwindtraders.com"
| sort _time
| streamstats current=f last(dmarc_policy) as prev_policy by queried_domain
| where (prev_policy="reject" AND dmarc_policy!="reject") OR (prev_policy="quarantine" AND dmarc_policy="none")
| table _time queried_domain prev_policy dmarc_policy
```

### Federation discovery

Search: a `Managed` tenant flips to `Federated`, or a federated
tenant changes IdP. Both indicate an identity-stack change worth
operator awareness.

```spl
index=recon sourcetype=recon:lookup
| streamstats current=f last(auth_type) as prev_auth_type by queried_domain
| where prev_auth_type!=auth_type
| table _time queried_domain prev_auth_type auth_type
```

## Files in this directory

- `props.conf` — Splunk sourcetype definition. Drop into
  `$SPLUNK_HOME/etc/system/local/` (or `apps/<your-app>/local/`).
- `savedsearches.conf` — three example saved searches matching the
  use cases above. Adjust schedules and `actions` to taste.
- `expected-splunk-event.json` — what a Splunk event looks like
  after `props.conf` extraction, given the
  `examples/sample-output.json` input. This is the contract the CI
  test verifies.

## Author of record

Maintainer-authored. **Vendor-unverified**: no Splunk employee has
QA'd this against a current Splunk Cloud / Splunk Enterprise build.
A PR from a Splunk customer / employee that fixes any conf-file
syntax drift is welcome.
