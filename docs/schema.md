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
| `recon batch <file> --json --include-ecosystem` | a `BatchResult` wrapper object `{domains, ecosystem_hyperedges}` | `domains` elements are success objects or `BatchErrorRecord`; the wrapper remains present even when no domain resolves |
| `recon batch <file> --ndjson` | one JSON object per line (newline-delimited) | each line is a success object or a `BatchErrorRecord` |
| `recon delta <domain> --json` / `recon <domain> --compare <file> --json` | a single `DeltaReport` object | n/a |
| `recon batch <file> --summary --json` | a single `cohort_summary` object (`record_type: "cohort_summary"`, `schema_version: "2.1"` by default; select `--summary-schema 2.2` explicitly) | n/a (aggregate-only; no per-domain records) |

The machine-readable form of each shape lives in
[`recon-schema.json`](recon-schema.json): the document root is the
single-domain success object; `$defs/BatchArray`, `$defs/BatchResult`,
`$defs/BatchNdjsonRecord`, `$defs/BatchErrorRecord`, and `$defs/DeltaReport`
cover the rest.

The `cohort_summary` mode (`recon batch --summary`) is a versioned aggregate-only
document, distinct from the `"2.0"` single-domain record. The released 2.1
contract remains the default. `--summary-schema 2.2` opts into fresh
contract-scoped DMARC rates, corrected missing-value handling, and explicit
metric kinds. The downstream reducer exposes the same selection through
`--schema-version`; its 2.2 DMARC projection is atemporal because stable tenant
JSON omits observation time. These cohort identifiers select exact contracts;
they are not package SemVer ranges. Changing the default or removing 2.1 would
require the deprecation window and package-major release in
[`stability.md`](stability.md). Neither version reports per-domain records, and
the two transient 2.2 projections are never emitted. Shape and small-cell policy are documented in
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
- For a single-domain lookup, only `error_type="no_data"` maps to `3`.
  Aggregate timeout, `all_sources_failed`, and unknown structured resolver
  failures are caught pipeline failures and map to `4`.
- On `2`, `3`, and `4` the `--json` modes write no JSON to stdout, so a consumer
  should check the exit code before parsing. On success, `--verbose` diagnostics
  use stderr and do not prefix the JSON payload.
- `recon fingerprints check` (the bundled fingerprint validator) returns `0`
  when every entry passes, `1` when any entry fails or a duplicate slug is
  found, and `2` when the path is missing or holds no YAML.

---

## Top-level object

A successful single-domain `recon <domain> --json` lookup returns one object
with the following fields. Other JSON modes use the shapes in the output-mode
table above. Field order in emitted JSON is not guaranteed; use the key name.

### Core identity

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `tenant_id` | string | yes | UUID | stable | Microsoft 365 tenant UUID when observed. `null` means no UUID was observed; it does not distinguish a non-M365 domain from unavailable, incomplete, or non-disclosing tenant discovery. |
| `display_name` | string | no | n/a | stable | Best available public display label, which may be an identity-provider federation brand; falls back to the queried domain. It is not a verified legal organization name or ownership claim. |
| `default_domain` | string | no | n/a | stable | Primary domain within the tenant. Falls back to the queried domain when no tenant was detected. |
| `queried_domain` | string | no | n/a | stable | The registrable apex (eTLD+1) recon analyzed, after validating and normalizing the input. A pasted URL or sub-host is reduced to its apex (`mail.acme.co.uk` → `acme.co.uk`); `--exact` keeps the literal host. |

### Provider & confidence

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `provider` | string | no | n/a | stable | Evidence-role summary of MX delivery paths, gateways, and possible downstream indicators (e.g. `"Microsoft 365 (MX delivery path) + Proofpoint gateway (MX delivery path)"`). Joined entries have no primary or secondary ordering semantics and do not prove complete product use. |
| `confidence` | string | no | `high \| medium \| low` | stable | Deterministic merged-output summary tier derived from source, same-claim corroboration, and degradation heuristics; not confidence in every claim or a calibrated probability. |
| `evidence_confidence` | string | no | `high \| medium \| low` | stable | Count-based confidence from distinct, error-free sources contributing useful data. |
| `inference_confidence` | string | no | `high \| medium \| low` | stable | Strength of the strongest error-free, same-claim corroboration chain; unrelated claims do not combine. |
| `region` | string | yes | e.g. `NA`, `EU`, `WW` | stable | Geographic region when detectable via OIDC. |
| `auth_type` | string | yes | `Federated \| Managed` | stable | M365 authentication style. |
| `google_auth_type` | string | yes | `Federated \| Managed` | stable | Google Workspace authentication style. |
| `google_idp_name` | string | yes | e.g. `Okta`, `Ping Identity` | stable | Third-party IdP name for GWS when detectable. |
| `primary_email_provider` | string | yes | n/a | stable | Schema-compatible field containing provider names observed directly in MX. Joined values are an unordered set and do not assert primacy. |
| `likely_primary_email_provider` | string | yes | n/a | stable | Possible downstream provider indicator from non-MX role evidence when MX names only a gateway. It is not a primary-provider claim. |
| `email_gateway` | string | yes | n/a | stable | MX-detected email security gateway (Proofpoint, Mimecast, etc.). |

### Sources & degradation

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `sources` | `list[string]` | no | subset of source names | stable | Distinct source names from error-free results that contributed useful data. |
| `partial` | bool | no | n/a | stable | `true` when a **core** source or core collector-channel marker is in `degraded_sources`. CT-only degradation does not flip this flag, matching `docs/recon-schema.json`. |
| `degraded_sources` | `list[string]` | no | n/a | stable | Stable source, collector-channel, or detector identifiers that failed or were unavailable, such as `dns_records`, `dns:dmarc`, `dns:mx`, or `detector:email_security`. Values can be finer-grained than top-level `sources`; an unavailable channel is unobserved, not a negative result. |

### Services & detection

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `services` | `list[string]` | no | n/a | stable | Human-readable labels derived from public fingerprints and reviewed rules; not proof of active product use. |
| `slugs` | `list[string]` | no | n/a | stable | Stable identifiers for observed fingerprint patterns; not product-use claims. |
| `detection_scores` | object | no | `{slug: score_level}` | stable | Per-slug evidence-strength level (`"low" \| "medium" \| "high"`), not a probability or truth confidence. |
| `insights` | `list[string]` | no | n/a | stable | Derived, hedged observations from public evidence. Exact wording may evolve; they are not verified private-state intelligence or proof of product use. |

### Domains

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `domain_count` | int | no | `0+` | stable | Number of domain strings retained from bounded public tenant-discovery responses. It is not organization size or guaranteed tenant cardinality. |
| `tenant_domains` | `list[string]` | no | n/a | stable | Domain strings retained from bounded public tenant-discovery responses. The list may be incomplete and does not establish ownership or an exhaustive tenant namespace. |
| `related_domains` | `list[string]` | no | n/a | stable | Domain names linked by bounded CNAME, CT, or autodiscover breadcrumbs. The stable field name does not imply ownership or an organizational relationship. |
| `surface_attributions` | `list[SurfaceAttribution]` | no | n/a | stable | Per-subdomain attribution of each related domain to a SaaS or infrastructure provider, from CNAME-chain classification. Empty when nothing classified. See the [`SurfaceAttribution`](#surfaceattribution) nested object. |

### Email security

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `email_security_score` | int | no | `0-5` | stable | Compatibility count of five observed-present public controls: effectively enforcing DMARC, DKIM selectors, SPF strict (`-all`), MTA-STS, and BIMI. If a constituent channel is unavailable, the count is incomplete; consult `degraded_sources` rather than treating uncounted controls as completed negatives. |
| `dmarc_policy` | string | yes | `reject \| quarantine \| none` | stable | Parser-valid explicit apex `p=` value. Under RFC 9989, a missing or invalid `p`, or invalid `sp` or `np`, can invoke an effective-none fallback only when `rua` contains a syntactically valid URI. recon retains the DMARC service and raw evidence for that fallback but leaves this field null rather than fabricating an explicit `p=none`. |
| `dmarc_pct` | int | yes | `0-100` | stable | Historic RFC 7489 `pct=` parameter retained as a compatibility extension; RFC 9989 removed it from the active grammar. |
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
| `bimi_identity` | object | yes | n/a | stable | BIMI VMC identity from a trust-validated source: `{organization, country, state, locality, trademark}`. The current opt-in document probe does not populate this field from an unverified certificate subject. |
| `evidence_conflicts` | `list[EvidenceConflict]` | no | n/a | stable (v1.7+) | Disagreements among the six tracked merged fields: each entry preserves the candidate values from 2+ sources. An empty array means no disagreement was recorded for those fields, not that every claim-bearing field agreed. |
| `chain_motifs` | `list[ChainMotif]` | no | n/a | stable (v1.7+) | CNAME chain motifs that fired on related subdomains, e.g. Cloudflare → AWS origin, Akamai → Azure origin. Observable proxy/origin shape only; never an ownership claim. Catalog at `recon_tool/data/motifs.yaml`. |
| `infrastructure_clusters` | `InfrastructureClusterReport` | no | always | stable (v1.8+) | CT co-occurrence community detection report. `algorithm` ∈ {`louvain`, `connected_components`, `skipped`}; `modularity` is 0.0 in fallback / skipped paths. `partition_stability` / `stability_runs` (additive, 2.2.0+) report the Louvain seed-sweep consensus (mean pairwise ARI; null outside the Louvain path). Members sorted; clusters sorted by size desc. |
| `fingerprint_metadata` | `dict[string, FingerprintMetadata]` | no | always | stable (v1.8+) | Per-slug `{product_family, parent_vendor, bimi_org}` typed catalog or grouping metadata. Slugs without metadata are omitted. Empty object when nothing applies. It drives exact batch hyperedge labels and never implies ownership, administrative control, or a business relationship. |

### Bayesian fusion fields (stable v2.0+)

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `slug_confidences` | `object` | no | map `{slug: score}`, `score` in `[0, 1]` | stable (v2.0+) | Per-slug evidence-strength scores from a Beta-shaped additive heuristic over retained positive evidence occurrences, parallel to `detection_scores`. Occurrences are not asserted independent, and scores are not externally calibrated probabilities. Populated only when fusion runs (see `fusion_enabled`). Reshaped from a positional pair array to an object map in v2.0 (SH2). See [`fusion.py`](../src/recon_tool/fusion.py). |
| `posterior_observations` | `list[PosteriorObservation]` | no | always present (empty when fusion off) | stable (v2.0+) | Model-relative marginal posteriors over the Bayesian network's high-level claims (M365 tenant, federated identity, email-policy enforcement, CDN fronting, and so on), each with an 80% evidence-responsive uncertainty band. Populated only when fusion runs (see `fusion_enabled`); empty array otherwise. See the [`PosteriorObservation`](#posteriorobservation-v20) nested object. |
| `fusion_enabled` | bool | no | n/a | stable (v2.0+) | True when the default-on evidence-strength and Bayesian-network post-processing ran (SH6). When false, `slug_confidences` is an empty object and `posterior_observations` is an empty array. When true, `slug_confidences` can still be empty if no retained evidence carries a slug, while `posterior_observations` carries the network's fixed nodes. |
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

`field` is one of: `display_name`, `auth_type`, `region`, `tenant_id`,
`dmarc_policy`, `google_auth_type`. The conflict-aware merger picks a winner
using the contributing source result's overall completeness tier. Candidate
`confidence` is that source-result tier, not field-specific reliability or
calibrated truth confidence. The array surfaces alternates so consumers can see
what was discarded. Other claim-bearing fields do not yet have complete
first-class conflict coverage.

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

- `louvain`: graph fits inside the 500-node cap; the Louvain heuristic returned
  a partition.
- `connected_components`: graph above cap; deterministic fallback. `modularity` is 0.0.
- `skipped`: empty graph or no edges. `clusters` is empty.

`partition_stability` (number or null, additive, 2.2.0+) is the partition
consensus across a Louvain seed sweep: the mean pairwise adjusted Rand
index between the partitions produced by `stability_runs` distinct seeds
(CAL11). 1.0 means every seed landed on the identical partition; lower values
show optimizer seed sensitivity on that one fixed graph. They do not measure CT
data stability, model stability, significance, or partition correctness. It is `null`
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
- `shared_slugs`: pairwise overlap of at least 3 detected slugs after the
  batch-local ubiquitous-slug filter. `key` is the comma-joined intersection.

Surfaced under the top-level `ecosystem_hyperedges` array of the batch
JSON wrapper when `recon batch --json --include-ecosystem` is run. The
batch wrapper shape is `{ecosystem_hyperedges: [...], domains: [...]}`
in that mode; otherwise the batch JSON is just the per-domain array. The
wrapper is still emitted when every domain fails, with an empty edge array and
the errors under `domains`.

The current implementation retains at most 200 hyperedges and at most 100
members per hyperedge. The v2 shape does not yet report omitted counts, so an
absent edge after either cap is not evidence that no such overlap existed. The
roadmap requires explicit completeness and omission diagnostics before this
surface can support exhaustive-correlation claims.

### Batch-only cross-domain fields (`batch --json`)

In `recon batch --json` output (the non-streaming path), a per-domain
success object may carry up to three additional keys that the
single-domain contract never emits. They are populated only when the
batch surfaced a typed overlap between two or more domains, and never
appear in single-domain `--json` or in `--ndjson` (which streams each
record before the batch-wide pass can run):

| Field | Type | Emitted when |
|---|---|---|
| `shared_verification_tokens` | `list[{token, peer}]` | two or more batch domains shared a TXT verification token |
| `shared_tenant` | `list[{tenant_id, peers}]` | two or more batch domains shared an M365 `tenant_id` |
| `shared_display_name` | `list[{display_name, normalized_name, peers}]` | two or more batch domains normalized to the same display name (hedged: customer-supplied brand text, not cryptographic) |

For resource bounds, a verification token observed on more than 200 batch
domains is not expanded into its quadratic peer list. The current per-domain
v2 field has no omission counter, so absence of `shared_verification_tokens` in
a batch larger than that cap is not a completeness claim. A future additive
batch diagnostic must report high-cardinality omissions before this surface can
support exhaustive-correlation claims.

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

All string fields; all except `organization` nullable. Stability: stable. The
top-level field remains null when no trust-validated identity source is
available, including when the opt-in BIMI probe observes only a certificate
document without validating its chain and VMC profile.

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
| `posterior` | number | stable (v2.0+) | P(node=present \| observed evidence) under the committed manually encoded, partly development-corpus-informed model, in `[0, 1]`. |
| `interval_low` | number | stable (v2.0+) | Lower bound of the 80% evidence-responsive uncertainty band. This is not a Bayesian credible interval or frequentist confidence interval; see `correlation.md`. |
| `interval_high` | number | stable (v2.0+) | Upper bound of the 80% evidence-responsive uncertainty band. |
| `n_eff` | number | stable (v2.0+) | Effective display mass used to construct the band; lower usually means wider for a fixed posterior. Floors at 4. |
| `sparse` | bool | stable (v2.0+) | `true` when `n_eff` is at the configured floor. It identifies the minimum display-mass case, not a calibrated uncertainty level or a statement about whether informative absence was counted. |
| `evidence_used` | `list[string]` | stable (v2.0+) | Bound observations that fired, formatted `slug:<name>` or `signal:<name>`. |
| `conflict_provenance` | `list[string]` | stable (v2.0+) | Cross-source disagreements that contributed to this node's `n_eff` penalty (v1.9.1+). Empty when none. |
| `evidence_ranked` | `list[NodeEvidence]` | stable (v1.9.3.2+) | Fired bindings ranked by absolute LLR contribution, descending (the contributing set, one per correlation group). Empty when nothing fired; omitted on batch records, whose shape predates it. |
| `entropy_reduction_nats` | number | stable, additive (2.2.0+) | Signed marginal entropy change H(prior marginal) - H(posterior) in nats. It can be negative, is not pointwise information gain, and the sum can double count dependent nodes. |
| `unit_counterfactuals` | `list[NodeUnitCounterfactual]` | stable, additive (2.2.0+) | Exact leave-one-unit-out counterfactuals for every evidence unit informative for this node, sorted by absolute `delta` descending. See the sub-table below. |

#### `NodeUnitCounterfactual` (2.2.0+)

One evidence unit's exact leave-one-out influence on the node's posterior:
the engine re-runs exact inference with the unit masked as *structurally
unobserved* (not "observed to be absent" - the distinction matters on the
declarative policy node) and reports the counterfactual. The mask is global
across the DAG, so `posterior_without` reflects everything else still
observed, including support flowing from other nodes' evidence through the
CPTs. This is an evidence counterfactual over the model, never a causal
claim about the world, and the deltas are individually exact but **not
additive** - units interact through the DAG.

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
fields are `evidence` (`--explain`), `explanation_dag` (`--explain` through
the CLI or `lookup_tenant` MCP tool), and `unclassified_cname_chains`
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

### `explanation_dag` (present with `--explain` through CLI or MCP)

Stability: **stable, schema version 1**. The exact top-level keys are:

- `nodes`: occurrence-aware evidence and fired-rule nodes plus shared slug,
  signal, insight, observation, and confidence nodes. Fired-rule occurrences
  are terminal-scoped so an identical rule label cannot cross-connect two
  explanations.
- `edges`: directed `{source, target, relation}` records. Current relations are
  `detected-by` (evidence to slug), `matched-rule` (evidence to rule only when
  the retained `EvidenceRecord.rule_name` exactly equals the fired-rule label),
  `contributes-to` (slug to explanation terminal), and `fired` (rule to
  explanation terminal). When that exact rule association was not retained,
  evidence reaches the terminal through its slug and recon does not invent a
  rule-specific edge.
- `schema_version`: integer `1`.
- `provenance_complete`: `true` exactly when every signal, insight,
  observation, and confidence terminal is reachable from at least one evidence
  node.
- `disconnected_terminals`: sorted terminal node IDs that are not reachable
  from evidence. An empty list accompanies `provenance_complete=true`.

The completeness fields are additive and optional in schema version 1 so
previously captured DAG objects remain valid; current recon versions always
emit both. They diagnose the graph actually emitted. They do not
manufacture an evidence link for a conclusion whose generator did not retain
one. The flat `explanations` list remains available alongside this additive
graph.

Current insight and posture explanations reconstruct some generator lineage
from human-facing text or rule proxies. `provenance_complete=true` therefore
means every terminal is reachable in the emitted reconstructed graph; it does
not prove that every generator association is exact. The first internal DMARC
claim contract retains exact evaluator lineage from a collector-retained raw
record to its signed atom. It operates after resolution and uses whole-resolution
completion time because a per-query timestamp is not retained. Its dossier is
not integrated into this stable public explanation schema.

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
  "changed_domain_count": null,
  "incomplete_comparison": null
}
```

Each `changed_*` field is either an object with `from` and `to`, or `null`.
`null` can mean no detected change among comparable values or that the field
was withheld; consult `incomplete_comparison.suppressed_fields` to distinguish
those cases. A null `incomplete_comparison` means the current comparator
recorded no degradation-triggered suppression. It does not prove complete
observation opportunity or equivalence of collection options, software,
catalog, model, cache, time, or resolver vantage. A non-null diagnostic names
the union in `degraded_sources`, the endpoint-specific
`previous_degraded_sources` and `current_degraded_sources`, and the withheld
fields. Prior degradation can make an apparent addition unidentifiable; current
degradation can make an apparent removal unidentifiable; a dependent scalar
change requires the relevant opportunity at both endpoints. Exit codes for
`recon delta` match the main CLI; see [Exit codes](#exit-codes).

CT-only degradation leaves `changed_auth_type` and `changed_domain_count`
comparable. It leaves `changed_confidence` comparable only when every degraded
endpoint has a non-null `ct_provider_used`, which records successful live
fallback or cache recovery. Without that recovery marker, recon withholds the
confidence change because collection failure can itself lower confidence.

`added_signals` and `removed_signals` are best-effort reconstructions from
rendered insight text so older exported snapshots remain comparable. They are
not raw signal-registry event logs. Current collection degradation suppresses
signal removals, and previous collection degradation suppresses signal
additions, rather than turning unavailable evidence into a temporal change.

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
