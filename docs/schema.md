# JSON Output Schema

This document is the stable contract for `recon <domain> --json` output,
current as of v2.0. Any field marked **stable** will not change shape or type
between patch or minor releases; removing or renaming one requires a major
version bump and a deprecation window. Consumers should ignore unknown fields:
additive changes (new fields) are non-breaking within the 2.x line.

For the broader stability policy, see [`stability.md`](stability.md).

Conformance tests at `tests/test_json_schema_contract.py` assert that every
documented field is present and correctly typed on a fixture TenantInfo.

---

## Output modes

`recon` emits more than one JSON shape. The top-level object documented
below is the shape of one mode only: a successful single-domain lookup.
The table tells you what to expect from each mode so you can pick a parser
without guessing.

| Invocation | Top-level shape | Per-record shape |
|---|---|---|
| `recon <domain> --json` | a single object | the top-level object below (success), or exit code 2/3 with no JSON on validation/no-data failures |
| `recon batch <file> --json` | a bare JSON array, one element per input domain in file order | each element is either a success object (the top-level object below) or a `BatchErrorRecord` |
| `recon batch <file> --json --include-ecosystem` | a `BatchResult` wrapper object `{domains, ecosystem_hyperedges}` | `domains` elements are success objects or `BatchErrorRecord`; falls back to the bare array when no domain resolved |
| `recon batch <file> --ndjson` | one JSON object per line (newline-delimited) | each line is a success object or a `BatchErrorRecord` |
| `recon delta <domain>` / `recon <domain> --compare <file>` | a single `DeltaReport` object | n/a |
| `recon batch <file> --summary [--json]` | a single `cohort_summary` object (`record_type: "cohort_summary"`, `schema_version: "2.1"`) | n/a (aggregate-only; no per-domain records) |

The machine-readable form of each shape lives in
[`recon-schema.json`](recon-schema.json): the document root is the
single-domain success object; `$defs/BatchArray`, `$defs/BatchResult`,
`$defs/BatchNdjsonRecord`, `$defs/BatchErrorRecord`, and `$defs/DeltaReport`
cover the rest.

The `cohort_summary` mode (`recon batch --summary`) is a v2.1 aggregate-only
document with its own `schema_version` (`"2.1"`, distinct from the `"2.0"` of the
single-domain record). It reports cohort statistics with no per-domain records;
its shape and the small-cell suppression policy are documented in
[`aggregate-state.md`](aggregate-state.md). It is not part of the v2.0
single-domain contract and is not yet mirrored in `recon-schema.json`.

### `BatchErrorRecord` (batch / NDJSON only)

When a single domain in a batch run fails (input validation or a lookup
error), recon emits an error record in place of the success object rather
than dropping the domain silently:

```json
{"domain": "not a domain", "error": "invalid domain syntax", "error_kind": "validation", "record_type": "error"}
```

Four keys: `domain` and `error` (both strings), `error_kind` (enum:
`validation`, `lookup`, `timeout`), and `record_type` (const `"error"`).
The shape is disjoint from the single-domain success object (which carries
dozens of required fields), so a consumer can branch on the key set alone.
The deterministic rule a consumer should apply to any batch / NDJSON record:

- `record_type` is `"error"` (or the key set is `{domain, error, error_kind, record_type}`) -> error record;
- key set is a superset of the required single-domain fields -> success object;
- anything else -> malformed, reject.

That rule is implemented for in-process consumers as
`recon_tool.schema_contract.classify_batch_record`, and exercised against a
synthetic batch sample in `tests/test_batch_ndjson_schema.py`. A success
object in batch `--json` may carry the extra batch-only cross-domain fields
described under [Batch-only cross-domain fields](#batch-only-cross-domain-fields-batch---json);
those keep it a superset of the required set, so the rule still classifies
it as a success object.

---

## Exit codes

The CLI returns a small, stable set of process exit codes so a script can
branch on the outcome without parsing output. They are defined in one place,
`recon_tool/exit_codes.py`, and shared by the CLI and the MCP server entry
point.

| Code | Name | Meaning |
|---|---|---|
| `0` | success | The command completed and produced its output. |
| `1` | general error | An unexpected or uncaught failure, plus a few handled fallbacks that are neither a clean validation nor a no-data case (an optional MCP dependency missing, an unexpected MCP server fault). This is also the Python default for an uncaught exception, so it covers paths recon does not explicitly classify. |
| `2` | validation error | Input recon rejected before doing work: a malformed domain, a missing file, mutually exclusive flags, or a refused unsafe invocation. No JSON is emitted on this path. |
| `3` | no data | The target resolved but no information was available. No JSON is emitted on this path. |
| `4` | internal error | A network or pipeline failure recon caught and classified itself, rather than letting it surface as an uncaught `1`. |

Notes for scripters:

- Codes `2`, `3`, and `4` are emitted deliberately by the lookup and delta
  paths; `1` is the general fallback; `0` is success. `recon delta` and
  `recon <domain> --compare <file>` follow the same contract.
- On `2` and `3` the `--json` modes write no JSON to stdout, so a consumer
  should check the exit code before parsing.
- `recon fingerprints check` (the bundled fingerprint validator) returns `0`
  when every entry passes, `1` when any entry fails or a duplicate slug is
  found, and `2` when the path is missing or holds no YAML.

---

## Top-level object

Every `--json` invocation returns a single JSON object with the following
fields. Field order in the emitted JSON is not guaranteed; use the key name.

### Core identity

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `tenant_id` | string | yes | UUID | stable | Microsoft 365 tenant UUID. `null` for non-M365 domains. |
| `display_name` | string | no | n/a | stable | Organization display name. Falls back to the queried domain when no better signal is available. |
| `default_domain` | string | no | n/a | stable | Primary domain within the tenant. Falls back to the queried domain when no tenant was detected. |
| `queried_domain` | string | no | n/a | stable | The domain the user passed (after validation + lowercasing). |

### Provider & confidence

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `provider` | string | no | n/a | stable | One-line provider summary (e.g. `"Microsoft 365 (primary) via Proofpoint gateway + Google Workspace (secondary)"`). |
| `confidence` | string | no | `high \| medium \| low` | stable | Overall confidence in the merged result. |
| `evidence_confidence` | string | no | `high \| medium \| low` | stable | Confidence in detected fingerprint slugs. |
| `inference_confidence` | string | no | `high \| medium \| low` | stable | Confidence in derived insights. |
| `region` | string | yes | e.g. `NA`, `EU`, `WW` | stable | Geographic region when detectable via OIDC. |
| `auth_type` | string | yes | `Federated \| Managed` | stable | M365 authentication style. |
| `google_auth_type` | string | yes | `Federated \| Managed` | stable | Google Workspace authentication style. |
| `google_idp_name` | string | yes | e.g. `Okta`, `Ping Identity` | stable | Third-party IdP name for GWS when detectable. |
| `primary_email_provider` | string | yes | n/a | stable | MX-confirmed primary email provider. |
| `likely_primary_email_provider` | string | yes | n/a | stable | Inferred primary (hedged) when MX is a gateway and DKIM/TXT/OIDC points to a specific downstream. |
| `email_gateway` | string | yes | n/a | stable | MX-detected email security gateway (Proofpoint, Mimecast, etc.). |

### Sources & degradation

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `sources` | `list[string]` | no | subset of source names | stable | Source names that successfully contributed to the result. |
| `partial` | bool | no | n/a | stable | `true` when a **core** source (DNS / identity / CT-as-core) is in `degraded_sources`. CT-only degradation does not flip this flag, matching `docs/recon-schema.json`. |
| `degraded_sources` | `list[string]` | no | n/a | stable | Source names that failed or were unavailable. |

### Services & detection

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `services` | `list[string]` | no | n/a | stable | Human-readable service names (`"Microsoft 365"`, `"Slack"`, …). |
| `slugs` | `list[string]` | no | n/a | stable | Stable fingerprint slugs for programmatic matching. |
| `detection_scores` | object | no | `{slug: score_level}` | stable | Per-slug detection score: `"low" \| "medium" \| "high"` aggregated from evidence. |
| `insights` | `list[string]` | no | n/a | stable | Derived intelligence lines. Exact wording may evolve; presence and signal types are stable. |

### Domains

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `domain_count` | int | no | `0+` | stable | Number of domains in the tenant. |
| `tenant_domains` | `list[string]` | no | n/a | stable | All domains found in the tenant (M365 `tenant_domains` or equivalent). |
| `related_domains` | `list[string]` | no | n/a | stable | Domains inferred from CNAME breadcrumbs, CT logs, or autodiscover delegation. |
| `surface_attributions` | `list[SurfaceAttribution]` | no | n/a | stable | Per-subdomain attribution of each related domain to a SaaS or infrastructure provider, from CNAME-chain classification. Empty when nothing classified. See the [`SurfaceAttribution`](#surfaceattribution) nested object. |

### Email security

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `email_security_score` | int | no | `0-5` | stable | Count of the 5 email controls present: DMARC `reject`/`quarantine`, DKIM selectors, SPF strict (`-all`), MTA-STS, BIMI. |
| `dmarc_policy` | string | yes | `reject \| quarantine \| none` | stable | DMARC policy when a DMARC record is present. |
| `dmarc_pct` | int | yes | `0-100` | stable | DMARC `pct=` parameter. |
| `mta_sts_mode` | string | yes | `enforce \| testing \| none` | stable | MTA-STS policy mode. |
| `site_verification_tokens` | `list[string]` | no | n/a | stable | TXT tokens observed on the apex (`google-site-verification=`, `MS=`, etc.). |

### CT / certificate intelligence

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `ct_provider_used` | string | yes | `crt.sh \| certspotter \| crt.sh (cached) \| certspotter (cached)` | best-effort | Which CT provider answered, or `(cached)` suffix when data came from the per-domain CT cache. CT best-effort: not in the required set, may be absent. |
| `ct_subdomain_count` | int | no | `0+` | stable | Number of subdomains returned after filtering. |
| `ct_cache_age_days` | int | yes | `0+` | best-effort | Age of the CT cache entry in days when cached data was used. `null` when from a live provider. CT best-effort: not in the required set, may be absent. |
| `ct_attempt_outcome` | string | yes | open string | best-effort | CT-pipeline telemetry (which provider path was tried, or why CT was skipped). Best-effort and **not** part of the guaranteed stable contract; the value set may grow. |
| `cert_summary` | object | yes | n/a | stable | Nested object: `{cert_count, issuer_diversity, issuance_velocity, newest_cert_age_days, oldest_cert_age_days, top_issuers}`. `null` when no CT data was obtained. |

### Sovereignty & Microsoft tenant metadata

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `cloud_instance` | string | yes | open string; known: `microsoftonline.com`, `microsoftonline.us`, `partner.microsoftonline.cn` | stable | Microsoft cloud-sovereignty host from M365 OIDC discovery. Open string (not a closed enum) since v2.0 (SH4); Microsoft controls the value. |
| `tenant_region_sub_scope` | string | yes | `GCC \| DOD \| USGov` | stable | Gov-cloud disambiguation from M365 OIDC. |
| `msgraph_host` | string | yes | `graph.microsoft.com \| graph.microsoft.us` | stable | Authoritative Microsoft Graph host. |

### Additional metadata

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `lexical_observations` | `list[string]` | no | n/a | stable | Hedged observations from CT subdomain lexical taxonomy. |
| `bimi_identity` | object | yes | n/a | stable | BIMI VMC identity: `{organization, country, state, locality, trademark}`. |
| `evidence_conflicts` | `list[EvidenceConflict]` | no | n/a | stable (v1.7+) | Cross-source disagreements: each entry names a merged field where 2+ sources gave different values, with all candidates preserved. Empty array when sources agreed. |
| `chain_motifs` | `list[ChainMotif]` | no | n/a | stable (v1.7+) | CNAME chain motifs that fired on related subdomains, e.g. Cloudflare → AWS origin, Akamai → Azure origin. Observable proxy/origin shape only; never an ownership claim. Catalog at `recon_tool/data/motifs.yaml`. |
| `infrastructure_clusters` | `InfrastructureClusterReport` | no | always | stable (v1.8+) | CT co-occurrence community detection report. `algorithm` ∈ {`louvain`, `connected_components`, `skipped`}; `modularity` is 0.0 in fallback / skipped paths. `partition_stability` / `stability_runs` (additive, 2.2.0+) report the Louvain seed-sweep consensus (mean pairwise ARI; null outside the Louvain path). Members sorted; clusters sorted by size desc. |
| `fingerprint_metadata` | `dict[string, FingerprintMetadata]` | no | always | stable (v1.8+) | Per-slug `{product_family, parent_vendor, bimi_org}` for detected slugs that carry relationship hints in their fingerprint YAML. Slugs without metadata are omitted. Empty object when nothing applies. Drives the v1.8 ecosystem hypergraph; never an ownership assertion. |

### Bayesian fusion fields (stable v2.0+)

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `slug_confidences` | `object` | no | map `{slug: posterior}`, `posterior` in `[0, 1]` | stable (v2.0+) | Bayesian per-slug posterior means, parallel to `detection_scores`. Populated only when fusion runs (see `fusion_enabled`). Reshaped from a positional pair array to an object map in v2.0 (SH2). See [`fusion.py`](../recon_tool/fusion.py). |
| `posterior_observations` | `list[PosteriorObservation]` | no | always present (empty when fusion off) | stable (v2.0+) | Marginal posteriors over the Bayesian network's high-level claims (M365 tenant, federated identity, email-policy enforcement, CDN fronting, and so on), each with an 80% credible interval. Populated only when fusion runs (see `fusion_enabled`); empty array otherwise. See the [`PosteriorObservation`](#posteriorobservation-v20) nested object. |
| `fusion_enabled` | bool | no | n/a | stable (v2.0+) | True when the Bayesian fusion layer ran (SH6). Distinguishes an empty `slug_confidences` with fusion off from fusion having run and found no per-slug posteriors. `posterior_observations` always carries the network's fixed nodes when fusion runs, so it is non-empty whenever `fusion_enabled` is true. |
| `schema_version` | string | no | `"2.0"` | stable (v2.0+) | Contract version of this record (SH7), so a detached payload can be routed across a future 2.x to 3.0 boundary. |
| `record_type` | string | no | `lookup` | stable (v2.0+) | Output-mode discriminator (SH7); `lookup` on a single-domain success object. Batch wrappers, deltas, error records, and cohort summaries carry `batch_result` / `delta` / `error` / `cohort_summary`. |

---

## Nested objects

### `cert_summary`

```json
{
  "cert_count": 42,
  "issuer_diversity": 3,
  "issuance_velocity": 7,
  "newest_cert_age_days": 2,
  "oldest_cert_age_days": 730,
  "top_issuers": ["Let's Encrypt", "DigiCert", "Sectigo"],
  "wildcard_sibling_clusters": [
    {"names": ["api.example.com", "example.com", "www.example.com"]}
  ],
  "deployment_bursts": [
    {
      "window_start": "2024-05-01T12:00:00+00:00",
      "window_end": "2024-05-01T12:00:45+00:00",
      "span_seconds": 45,
      "names": ["api.example.com", "app.example.com", "www.example.com"]
    }
  ]
}
```

| Field | Type | Stability |
|---|---|---|
| `cert_count` | int | stable |
| `issuer_diversity` | int | stable |
| `issuance_velocity` | int (certs in last 90 days) | stable |
| `newest_cert_age_days` | int | stable |
| `oldest_cert_age_days` | int | stable |
| `top_issuers` | `list[string]` (up to 3) | stable |
| `wildcard_sibling_clusters` | `list[{names: [...]}]` | stable (v1.7+): each entry's `names` is the deduplicated, sorted concrete-name SANs from a single cert that also covered ≥1 wildcard SAN. Empty when no wildcard cert produced concrete siblings. Bounded (≤10 clusters, ≤20 names per cluster). |
| `deployment_bursts` | `list[CertBurst]` | stable (v1.7+): co-issuance cohorts within a 60s window with ≥3 distinct non-wildcard SANs. Output is relative (span_seconds + names) and never claims ownership. Bounded (≤8 bursts, ≤25 names per burst). |

`CertBurst`:

```json
{
  "window_start": "ISO-8601 UTC",
  "window_end": "ISO-8601 UTC",
  "span_seconds": 45,
  "names": ["a.example.com", "b.example.com", "c.example.com"]
}
```

### `EvidenceConflict` (v1.7+)

```json
{
  "field": "display_name",
  "candidates": [
    {"value": "Acme Corp", "source": "oidc", "confidence": "high"},
    {"value": "Acme Corporation", "source": "userrealm", "confidence": "medium"}
  ]
}
```

`field` is one of: `display_name`, `auth_type`, `region`, `tenant_id`, `dmarc_policy`, `google_auth_type`. The conflict-aware merger picks a winner using source-confidence ordering; the array surfaces the alternates so consumers can see what was discarded.

### `ChainMotif` (v1.7+)

```json
{
  "motif_name": "cloudflare_to_aws",
  "display_name": "Cloudflare → AWS origin",
  "confidence": "medium",
  "subdomain": "api.example.com",
  "chain": ["edge.cloudflare.net", "origin.amazonaws.com"]
}
```

`chain` is the matched subsequence of hops, not the full original CNAME chain. Each motif fires on observable structure only, never an ownership claim. The motif catalog is shipped in `recon_tool/data/motifs.yaml` and can be extended via `~/.recon/motifs.yaml` (additive only).

### `InfrastructureClusterReport` (v1.8+)

```json
{
  "algorithm": "louvain",
  "modularity": 0.42,
  "partition_stability": 0.93,
  "stability_runs": 8,
  "node_count": 18,
  "edge_count": 31,
  "clusters": [
    {
      "cluster_id": 0,
      "size": 5,
      "members": ["api.example.com", "auth.example.com", "id.example.com",
                  "login.example.com", "sso.example.com"],
      "shared_cert_count": 12,
      "dominant_issuer": "Let's Encrypt"
    }
  ]
}
```

`algorithm` is the detection path that produced the partition:

- `louvain`: graph fits inside the 500-node cap; partition is meaningful.
- `connected_components`: graph above cap; deterministic fallback. `modularity` is 0.0.
- `skipped`: empty graph or no edges. `clusters` is empty.

`partition_stability` (number or null, additive, 2.2.0+) is the partition
consensus across a Louvain seed sweep: the mean pairwise adjusted Rand
index between the partitions produced by `stability_runs` distinct seeds
(CAL11). 1.0 means every seed landed on the identical partition; lower
values flag the partition degeneracy a single modularity score cannot see
(near-equal-modularity partitions that differ structurally). It is `null`
outside the Louvain path, where the partition is deterministic and the
measure is not applicable; the *reported* clusters always come from the
fixed shipped seed, so output stays deterministic.

Each cluster member is a SAN hostname. Clusters describe **observed
co-issuance** (names that show up on the same certificates), never
ownership. Raw edge data is not emitted in the default `--json`
envelope; use the `export_graph` MCP tool when you need it.

### `FingerprintMetadata` (v1.8+)

```json
{
  "product_family": "Microsoft 365",
  "parent_vendor": "Microsoft",
  "bimi_org": null
}
```

All three fields are optional. At least one is non-null in every
emitted record. Surfaced under the top-level `fingerprint_metadata`
object, keyed by detected slug.

### `EcosystemHyperedge` (v1.8+, batch-only)

```json
{
  "edge_type": "top_issuer",
  "key": "Let's Encrypt",
  "members": ["a.example.com", "b.example.com"]
}
```

`edge_type` is one of:

- `top_issuer`: domains share their CT top-issuer name.
- `bimi_org`: domains share a BIMI VMC organization (light-normalised).
- `parent_vendor`: domains have ≥1 detected slug carrying the same `parent_vendor` metadata.
- `shared_slugs`: pairwise overlap of ≥2 detected slugs. `key` is the comma-joined intersection.

Surfaced under the top-level `ecosystem_hyperedges` array of the batch
JSON wrapper when `recon batch --json --include-ecosystem` is run. The
batch wrapper shape is `{ecosystem_hyperedges: [...], domains: [...]}`
in that mode; otherwise the batch JSON is just the per-domain array. One
edge case: if `--include-ecosystem` is set but no domain in the batch
resolved successfully, there is nothing to build a hypergraph from, so
the output falls back to the bare per-domain array (which then holds only
`BatchErrorRecord` entries).

### Batch-only cross-domain fields (`batch --json`)

In `recon batch --json` output (the non-streaming path), a per-domain
success object may carry up to three additional keys that the
single-domain contract never emits. They are populated only when the
batch surfaced a relationship between two or more domains, and never
appear in single-domain `--json` or in `--ndjson` (which streams each
record before the batch-wide pass can run):

| Field | Type | Emitted when |
|---|---|---|
| `shared_verification_tokens` | `list[{token, peer}]` | two or more batch domains shared a TXT verification token |
| `shared_tenant` | `list[{tenant_id, peers}]` | two or more batch domains shared an M365 `tenant_id` |
| `shared_display_name` | `list[{display_name, normalized_name, peers}]` | two or more batch domains normalized to the same display name (hedged: customer-supplied brand text, not cryptographic) |

These are additive: they leave the record a superset of the required
single-domain fields, so the batch-record rule still classifies it as a
success object.

### `bimi_identity`

```json
{
  "organization": "Contoso Ltd",
  "country": "US",
  "state": "WA",
  "locality": "Redmond",
  "trademark": "CONTOSO"
}
```

All string fields; all except `organization` nullable. Stability: stable.

### `SurfaceAttribution`

One entry per classified related subdomain, in the top-level
`surface_attributions` array.

```json
{
  "subdomain": "api.example.com",
  "primary_slug": "cloudflare",
  "primary_name": "Cloudflare",
  "primary_tier": "application",
  "infra_slug": "amazonaws",
  "infra_name": "AWS"
}
```

| Field | Type | Nullable | Stability | Description |
|---|---|---|---|---|
| `subdomain` | string | no | stable | The related subdomain attributed. |
| `primary_slug` | string | no | stable | Slug of the primary provider the CNAME chain resolves to. |
| `primary_name` | string | no | stable | Human-readable primary provider name. |
| `primary_tier` | string | no | stable | Provider tier: `application` or `infrastructure`. |
| `infra_slug` | string | yes | stable | Underlying infrastructure slug when the primary fronts another provider; `null` when none. |
| `infra_name` | string | yes | stable | Human-readable infrastructure name; `null` when none. |

Derived from CNAME-chain classification of `related_domains`; observable
proxy/origin shape only, never an ownership claim.

### `PosteriorObservation` (v2.0+)

One entry per Bayesian-network node, present in the `posterior_observations`
array when fusion runs (empty array otherwise).

```json
{
  "name": "m365_tenant",
  "description": "Domain has a Microsoft 365 / Entra tenant.",
  "posterior": 0.97,
  "interval_low": 0.91,
  "interval_high": 1.0,
  "evidence_used": ["slug:microsoft365", "slug:entra-id"],
  "n_eff": 6.0,
  "sparse": false,
  "conflict_provenance": [],
  "evidence_ranked": [
    {"kind": "slug", "name": "microsoft365", "llr": 3.4549, "influence_pct": 100.0}
  ],
  "entropy_reduction_nats": 0.4773,
  "unit_counterfactuals": [
    {"unit": "m365_indicators", "kind": "group", "observed": "fired",
     "posterior_without": 0.3, "delta": 0.67}
  ]
}
```

| Field | Type | Stability | Description |
|---|---|---|---|
| `name` | string | stable (v2.0+) | Stable node identifier matching `bayesian_network.yaml`. |
| `description` | string | stable (v2.0+) | Plain-English claim the node encodes. |
| `posterior` | number | stable (v2.0+) | P(node=present \| observed evidence), in `[0, 1]`. |
| `interval_low` | number | stable (v2.0+) | Lower bound of the 80% credible interval (evidence-responsive, not frequentist coverage; see `correlation.md`). |
| `interval_high` | number | stable (v2.0+) | Upper bound of the 80% credible interval. |
| `n_eff` | number | stable (v2.0+) | Effective sample size behind the interval; lower means wider. Floors at 4. |
| `sparse` | bool | stable (v2.0+) | `true` when `n_eff` is at the floor and absence carried no disconfirming weight, the passive-observation ceiling for this node. |
| `evidence_used` | `list[string]` | stable (v2.0+) | Bound observations that fired, formatted `slug:<name>` or `signal:<name>`. |
| `conflict_provenance` | `list[string]` | stable (v2.0+) | Cross-source disagreements that contributed to this node's `n_eff` penalty (v1.9.1+). Empty when none. |
| `evidence_ranked` | `list[NodeEvidence]` | stable (v1.9.3.2+) | Fired bindings ranked by absolute LLR contribution, descending (the contributing set, one per correlation group). Empty when nothing fired; omitted on batch records, whose shape predates it. |
| `entropy_reduction_nats` | number | stable, additive (2.2.0+) | This node's share of the information recovered: H(prior marginal) − H(posterior) in nats, signed (negative when evidence widens the node). The per-node breakdown of the top-level total (CAL10). |
| `unit_counterfactuals` | `list[NodeUnitCounterfactual]` | stable, additive (2.2.0+) | Exact leave-one-unit-out counterfactuals for every evidence unit informative for this node, sorted by absolute `delta` descending. See the sub-table below. |

#### `NodeUnitCounterfactual` (2.2.0+)

One evidence unit's exact leave-one-out influence on the node's posterior:
the engine re-runs exact inference with the unit masked as *structurally
unobserved* (not "observed to be absent" — the distinction matters on the
declarative policy node) and reports the counterfactual. The mask is global
across the DAG, so `posterior_without` reflects everything else still
observed, including support flowing from other nodes' evidence through the
CPTs. This is an evidence counterfactual over the model, never a causal
claim about the world, and the deltas are individually exact but **not
additive** — units interact through the DAG.

| Field | Type | Description |
|---|---|---|
| `unit` | string | Evidence-unit name: a correlation-group name (`m365_indicators`, `dmarc_policy`) or an ungrouped binding's slug/signal name. |
| `kind` | string | `group`, `slug`, or `signal`. |
| `observed` | string | `fired`, or `absent` for an informative absence on a declarative node (there `delta` is typically negative). |
| `posterior_without` | number | P(node=present \| evidence with this unit masked), in `[0, 1]`. |
| `delta` | number | `posterior − posterior_without`: positive when the unit pushes the node up. |

The model, the asymmetric (MNAR) likelihood, and what the 80% interval does and
does not claim live in [`correlation.md`](correlation.md).

---

## Arrays of structured records (verbose modes)

When invoked with `--verbose` / `--full` / `--explain`, additional structured
arrays appear. These fields are conditional: they are absent unless the
relevant flag is passed, so a consumer should treat their presence as
optional and never infer "always present". They are intentionally omitted
from the schema's `required` list for the same reason. The conditional
fields are `evidence` (`--explain`), `explanation_dag` (`--explain` on the
`lookup_tenant` MCP tool), and `unclassified_cname_chains`
(`--include-unclassified`).

### `evidence` (present with `--explain`)

```json
[
  {
    "source_type": "TXT",
    "raw_value": "v=spf1 include:spf.protection.outlook.com ...",
    "rule_name": "SPF M365",
    "slug": "microsoft365"
  },
  ...
]
```

Stability: **stable** within the default/`--json` contract when `--explain`
is also passed; the fields inside each record (`source_type`, `raw_value`,
`rule_name`, `slug`) will not change shape.

### `explanation_dag` (present with `--explain` on `lookup_tenant` MCP tool)

Stability: **stable**. Top-level keys: `evidence`, `slugs`, `rules`,
`signals`, `insights`, each a list of records with `id` and references.

---

## Delta output (from `recon delta <domain>` and `--compare`)

`recon delta` and `recon <domain> --compare <file>` emit a separate
`DeltaReport` structure. Documented separately to avoid conflating with the
primary `lookup` contract.

Stability: stable.

```json
{
  "domain": "contoso.com",
  "added_services": ["Linear"],
  "removed_services": ["Asana"],
  "added_slugs": ["linear"],
  "removed_slugs": ["asana"],
  "added_signals": [],
  "removed_signals": [],
  "changed_auth_type": {"from": "Managed", "to": "Federated"},
  "changed_dmarc_policy": null,
  "changed_email_security_score": {"from": 3, "to": 4},
  "changed_confidence": null,
  "changed_domain_count": null
}
```

Each `changed_*` field is either `null` (no change) or an object with `from`
and `to`. Exit codes for `recon delta` match the main CLI; see
[Exit codes](#exit-codes).

---

## What is NOT in this contract

- Rich panel formatting (whitespace, colors, row ordering within
  categories); covered by `stability.md` "What's not in the stability
  contract".
- Insight text wording; the insight types and trigger conditions are
  stable, though exact phrasing may be refined.
- Which specific fingerprints fire for a given domain. The `slugs` field
  is stable as a mechanism; the contents depend on the fingerprint database
  version and may change as new fingerprints are added or refined.
- `cache_age_in_hours`, `cache_hit`, and other internal performance metrics
  that may appear in debug/verbose output but are not part of the stable
  contract.
