# JSON Output Schema

This document is the stable contract for `recon <domain> --json` output as
of v1.0. Any field marked **stable** will not change shape or type between
patch or minor releases; removing or renaming one requires a major version
bump and a deprecation window.

For the broader stability policy, see [`stability.md`](stability.md).

Conformance tests at `tests/test_json_schema_contract.py` assert that every
documented field is present and correctly typed on a fixture TenantInfo.

---

## Top-level object

Every `--json` invocation returns a single JSON object with the following
fields. Field order in the emitted JSON is not guaranteed; use the key name.

### Core identity

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `tenant_id` | string | yes | UUID | stable | Microsoft 365 tenant UUID. `null` for non-M365 domains. |
| `display_name` | string | no | — | stable | Organization display name. Falls back to the queried domain when no better signal is available. |
| `default_domain` | string | no | — | stable | Primary domain within the tenant. Falls back to the queried domain when no tenant was detected. |
| `queried_domain` | string | no | — | stable | The domain the user passed (after validation + lowercasing). |

### Provider & confidence

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `provider` | string | no | — | stable | One-line provider summary (e.g. `"Microsoft 365 (primary) via Proofpoint gateway + Google Workspace (secondary)"`). |
| `confidence` | string | no | `high \| medium \| low` | stable | Overall confidence in the merged result. |
| `evidence_confidence` | string | no | `high \| medium \| low` | stable | Confidence in detected fingerprint slugs. |
| `inference_confidence` | string | no | `high \| medium \| low` | stable | Confidence in derived insights. |
| `region` | string | yes | e.g. `NA`, `EU`, `WW` | stable | Geographic region when detectable via OIDC. |
| `auth_type` | string | yes | `Federated \| Managed` | stable | M365 authentication style. |
| `google_auth_type` | string | yes | `Federated \| Managed` | stable | Google Workspace authentication style. |
| `google_idp_name` | string | yes | e.g. `Okta`, `Ping Identity` | stable | Third-party IdP name for GWS when detectable. |
| `primary_email_provider` | string | yes | — | stable | MX-confirmed primary email provider. |
| `likely_primary_email_provider` | string | yes | — | stable | Inferred primary (hedged) when MX is a gateway and DKIM/TXT/OIDC points to a specific downstream. |
| `email_gateway` | string | yes | — | stable | MX-detected email security gateway (Proofpoint, Mimecast, etc.). |

### Sources & degradation

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `sources` | `list[string]` | no | subset of source names | stable | Source names that successfully contributed to the result. |
| `partial` | bool | no | — | stable | `true` when any `degraded_sources` is non-empty. |
| `degraded_sources` | `list[string]` | no | — | stable | Source names that failed or were unavailable. |

### Services & detection

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `services` | `list[string]` | no | — | stable | Human-readable service names (`"Microsoft 365"`, `"Slack"`, …). |
| `slugs` | `list[string]` | no | — | stable | Stable fingerprint slugs for programmatic matching. |
| `detection_scores` | object | no | `{slug: score_level}` | stable | Per-slug detection score: `"low" \| "medium" \| "high"` aggregated from evidence. |
| `insights` | `list[string]` | no | — | stable | Derived intelligence lines. Exact wording may evolve; presence and signal types are stable. |

### Domains

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `domain_count` | int | no | `0+` | stable | Number of domains in the tenant. |
| `tenant_domains` | `list[string]` | no | — | stable | All domains found in the tenant (M365 `tenant_domains` or equivalent). |
| `related_domains` | `list[string]` | no | — | stable | Domains inferred from CNAME breadcrumbs, CT logs, or autodiscover delegation. |

### Email security

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `email_security_score` | int | no | `0–5` | stable | Count of the 5 email controls present: DMARC `reject`/`quarantine`, DKIM selectors, SPF strict (`-all`), MTA-STS, BIMI. |
| `dmarc_policy` | string | yes | `reject \| quarantine \| none` | stable | DMARC policy when a DMARC record is present. |
| `dmarc_pct` | int | yes | `0–100` | stable | DMARC `pct=` parameter. |
| `mta_sts_mode` | string | yes | `enforce \| testing \| none` | stable | MTA-STS policy mode. |
| `site_verification_tokens` | `list[string]` | no | — | stable | TXT tokens observed on the apex (`google-site-verification=`, `MS=`, etc.). |

### CT / certificate intelligence

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `ct_provider_used` | string | yes | `crt.sh \| certspotter \| crt.sh (cached) \| certspotter (cached)` | stable | Which CT provider answered, or `(cached)` suffix when data came from the per-domain CT cache. |
| `ct_subdomain_count` | int | no | `0+` | stable | Number of subdomains returned after filtering. |
| `ct_cache_age_days` | int | yes | `0+` | stable | Age of the CT cache entry in days when cached data was used. `null` when data came from a live provider. |
| `cert_summary` | object | yes | — | stable | Nested object: `{cert_count, issuer_diversity, issuance_velocity, newest_cert_age_days, oldest_cert_age_days, top_issuers}`. `null` when no CT data was obtained. |

### Sovereignty & Microsoft tenant metadata

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `cloud_instance` | string | yes | `microsoftonline.com \| microsoftonline.us \| partner.microsoftonline.cn` | stable | Cloud sovereignty from M365 OIDC discovery. |
| `tenant_region_sub_scope` | string | yes | `GCC \| DOD \| USGov` | stable | Gov-cloud disambiguation from M365 OIDC. |
| `msgraph_host` | string | yes | `graph.microsoft.com \| graph.microsoft.us` | stable | Authoritative Microsoft Graph host. |

### Additional metadata

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `lexical_observations` | `list[string]` | no | — | stable | Hedged observations from CT subdomain lexical taxonomy. |
| `bimi_identity` | object | yes | — | stable | BIMI VMC identity: `{organization, country, state, locality, trademark}`. |
| `evidence_conflicts` | `list[EvidenceConflict]` | no | — | stable (v1.7+) | Cross-source disagreements: each entry names a merged field where 2+ sources gave different values, with all candidates preserved. Empty array when sources agreed. |
| `chain_motifs` | `list[ChainMotif]` | no | — | stable (v1.7+) | CNAME chain motifs that fired on related subdomains — e.g. Cloudflare → AWS origin, Akamai → Azure origin. Observable proxy/origin shape only; never an ownership claim. Catalog at `recon_tool/data/motifs.yaml`. |
| `infrastructure_clusters` | `InfrastructureClusterReport` | no | always | stable (v1.8+) | CT co-occurrence community detection report. `algorithm` ∈ {`louvain`, `connected_components`, `skipped`}; `modularity` is 0.0 in fallback / skipped paths. Members sorted; clusters sorted by size desc. |
| `fingerprint_metadata` | `dict[string, FingerprintMetadata]` | no | always | stable (v1.8+) | Per-slug `{product_family, parent_vendor, bimi_org}` for detected slugs that carry relationship hints in their fingerprint YAML. Slugs without metadata are omitted. Empty object when nothing applies. Drives the v1.8 ecosystem hypergraph; never an ownership assertion. |

### Experimental

| Field | Type | Nullable | Values | Stability | Description |
|---|---|---|---|---|---|
| `slug_confidences` | `list[[string, float]]` | no | pairs of `(slug, posterior)` with `posterior` in `[0, 1]` | **experimental** | Bayesian per-slug posterior means. Populated only when `--fusion` is passed. The algorithm, priors, and field shape may evolve in minor releases. See [`fusion.py`](../recon_tool/fusion.py). |

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
    ["api.example.com", "example.com", "www.example.com"]
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
| `wildcard_sibling_clusters` | `list[list[string]]` | stable (v1.7+) — each inner list is the deduplicated, sorted concrete-name SANs from a single cert that also covered ≥1 wildcard SAN. Empty when no wildcard cert produced concrete siblings. Bounded (≤10 clusters, ≤20 names per cluster). |
| `deployment_bursts` | `list[CertBurst]` | stable (v1.7+) — co-issuance cohorts within a 60s window with ≥3 distinct non-wildcard SANs. Output is relative (span_seconds + names) and never claims ownership. Bounded (≤8 bursts, ≤25 names per burst). |

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

`chain` is the matched subsequence of hops, not the full original CNAME chain. Each motif fires on observable structure only — never an ownership claim. The motif catalog is shipped in `recon_tool/data/motifs.yaml` and can be extended via `~/.recon/motifs.yaml` (additive only).

### `InfrastructureClusterReport` (v1.8+)

```json
{
  "algorithm": "louvain",
  "modularity": 0.42,
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

- `louvain` — graph fits inside the 500-node cap; partition is meaningful.
- `connected_components` — graph above cap; deterministic fallback. `modularity` is 0.0.
- `skipped` — empty graph or no edges. `clusters` is empty.

Each cluster member is a SAN hostname. Clusters describe **observed
co-issuance** — names that show up on the same certificates — never
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

- `top_issuer` — domains share their CT top-issuer name.
- `bimi_org` — domains share an exact BIMI VMC organization (light-normalised).
- `parent_vendor` — domains have ≥1 detected slug carrying the same `parent_vendor` metadata.
- `shared_slugs` — pairwise overlap of ≥2 detected slugs. `key` is the comma-joined intersection.

Surfaced under the top-level `ecosystem_hyperedges` array of the batch
JSON wrapper when `recon batch --json --include-ecosystem` is run. The
batch wrapper shape is `{ecosystem_hyperedges: [...], domains: [...]}`
in that mode; otherwise the batch JSON is just the per-domain array.

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

---

## Arrays of structured records (verbose modes)

When invoked with `--verbose` / `--full` / `--explain`, additional structured
arrays appear:

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
`signals`, `insights` — each a list of records with `id` and references.

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
and `to`. Exit codes for `recon delta` match the main CLI (0 success,
2 validation error, 3 no data).

---

## What is NOT in this contract

- Rich panel formatting (whitespace, colors, row ordering within
  categories) — covered by `stability.md` "What's not in the stability
  contract".
- Insight text wording — the insight types and trigger conditions are
  stable; exact phrasing may be refined.
- Which specific fingerprints fire for a given domain — the `slugs` field
  is stable as a mechanism; the contents depend on the fingerprint database
  version and may change as new fingerprints are added or refined.
- `cache_age_in_hours`, `cache_hit`, and other internal performance metrics
  that may appear in debug/verbose output but are not part of the stable
  contract.
