"""Non-Rich data serializers for TenantInfo.

The json-dict (the shared ``format_tenant_dict``), json, plain, and CSV
renderers, split out of ``formatter.py`` so the data-shaping layer lives apart
from the Rich panel code. Depends only on the models and the shared
classification helpers; it does no Rich rendering and imports nothing from
``formatter``. ``formatter`` re-exports the public serializers so the
``recon_tool.formatter`` import surface is unchanged.
"""

from __future__ import annotations

import json
from typing import Any

from recon_tool.email_security import compute_email_security_score
from recon_tool.formatter.classify import detect_provider, slug_to_relationship_metadata
from recon_tool.models import TenantInfo, serialize_conflicts_array
from recon_tool.validator import strip_control_chars


def format_tenant_dict(info: TenantInfo, *, include_unclassified: bool = False) -> dict[str, Any]:
    """Build a dict representation of TenantInfo (shared by JSON and batch).

    When ``include_unclassified`` is True, the resulting dict adds an
    ``unclassified_cname_chains`` array of ``{subdomain, chain}`` records
    for CNAME chains the surface classifier resolved but couldn't attribute.
    Off by default to keep the v2.0 schema contract narrow; opt-in for the
    fingerprint-discovery loop.
    """
    has_mx_records = any(e.source_type == "MX" for e in info.evidence)
    provider = detect_provider(
        info.services,
        info.slugs,
        primary_email_provider=info.primary_email_provider,
        email_gateway=info.email_gateway,
        likely_primary_email_provider=info.likely_primary_email_provider,
        has_mx_records=has_mx_records,
    )
    d: dict[str, Any] = {
        "tenant_id": info.tenant_id,
        "display_name": info.display_name,
        "default_domain": info.default_domain,
        "queried_domain": info.queried_domain,
        "provider": provider,
        "confidence": info.confidence.value,
        "evidence_confidence": info.evidence_confidence.value,
        "inference_confidence": info.inference_confidence.value,
        "region": info.region,
        "auth_type": info.auth_type,
        "dmarc_policy": info.dmarc_policy,
        "domain_count": info.domain_count,
        "sources": list(info.sources),
        "services": list(info.services),
        # Emit slugs explicitly. TenantInfo.slugs is the
        # canonical detected-fact identifier set — downstream
        # tooling matching on specific slugs had to read them out
        # of `detection_scores` before, which was awkward.
        "slugs": list(info.slugs),
        "insights": list(info.insights),
        "tenant_domains": list(info.tenant_domains),
        "related_domains": list(info.related_domains),
        # `partial` means "result is meaningfully incomplete" — reserve it for
        # core-source failures (OIDC, UserRealm, Google Identity, DNS), not
        # CT-provider degradation. crt.sh is chronically flaky and CertSpotter
        # rate-limits frequently; the CT pipeline handles both gracefully via
        # fallback + cache, so their degradation should NOT flip the global
        # `partial` flag. The per-source status is still surfaced in the
        # `degraded_sources` list for consumers who want the detail.
        "partial": any(src not in {"crt.sh", "certspotter"} for src in info.degraded_sources),
        "degraded_sources": list(info.degraded_sources),
        "google_auth_type": info.google_auth_type,
        "google_idp_name": info.google_idp_name,
        "mta_sts_mode": info.mta_sts_mode,
        "site_verification_tokens": list(info.site_verification_tokens),
        "primary_email_provider": info.primary_email_provider,
        "likely_primary_email_provider": info.likely_primary_email_provider,
        "email_gateway": info.email_gateway,
        "dmarc_pct": info.dmarc_pct,
        "ct_provider_used": info.ct_provider_used,
        "ct_subdomain_count": info.ct_subdomain_count,
        "ct_cache_age_days": info.ct_cache_age_days,
        "ct_attempt_outcome": info.ct_attempt_outcome,
        "slug_confidences": dict(info.slug_confidences),
        # v1.9 Bayesian network — populated only when --fusion is on.
        # ``conflict_provenance`` is always present per posterior;
        # empty list when no cross-source conflicts dampened the interval.
        # ``evidence_ranked`` ranks fired bindings by absolute
        # LLR contribution so consumers can surface the highest-leverage
        # evidence per node. Empty list when no bindings fired.
        "posterior_observations": [
            {
                "name": p.name,
                "description": p.description,
                "posterior": p.posterior,
                "interval_low": p.interval_low,
                "interval_high": p.interval_high,
                "evidence_used": list(p.evidence_used),
                "n_eff": p.n_eff,
                "sparse": p.sparse,
                "conflict_provenance": [
                    {
                        "field": c.field,
                        "sources": list(c.sources),
                        "magnitude": c.magnitude,
                    }
                    for c in p.conflict_provenance
                ],
                "evidence_ranked": [
                    {
                        "kind": e.kind,
                        "name": e.name,
                        "llr": e.llr,
                        "influence_pct": e.influence_pct,
                    }
                    for e in p.evidence_ranked
                ],
                # 2.2.0 evidence-semantics diagnostics (schema-additive):
                # the node's share of the recovered information, and the
                # exact leave-one-unit-out counterfactual per informative
                # evidence unit.
                "entropy_reduction_nats": p.entropy_reduction_nats,
                "unit_counterfactuals": [
                    {
                        "unit": c.unit,
                        "kind": c.kind,
                        "observed": c.observed,
                        "posterior_without": c.posterior_without,
                        "delta": c.delta,
                    }
                    for c in p.unit_counterfactuals
                ],
            }
            for p in info.posterior_observations
        ],
        # Surface email_security_score at the top level of --json
        # (previously only available inside the insights string).
        "email_security_score": compute_email_security_score(info),
        # Sovereignty + lexical fields
        "cloud_instance": info.cloud_instance,
        "tenant_region_sub_scope": info.tenant_region_sub_scope,
        "msgraph_host": info.msgraph_host,
        "lexical_observations": list(info.lexical_observations),
    }
    # v2.0 schema contract: always present (null when unavailable).
    if info.cert_summary is not None:
        d["cert_summary"] = {
            "cert_count": info.cert_summary.cert_count,
            "issuer_diversity": info.cert_summary.issuer_diversity,
            "issuance_velocity": info.cert_summary.issuance_velocity,
            "newest_cert_age_days": info.cert_summary.newest_cert_age_days,
            "oldest_cert_age_days": info.cert_summary.oldest_cert_age_days,
            "top_issuers": list(info.cert_summary.top_issuers),
            # Wildcard SAN sibling clusters; empty list when no
            # wildcard cert produced siblings.
            "wildcard_sibling_clusters": [
                {"names": list(cluster)} for cluster in info.cert_summary.wildcard_sibling_clusters
            ],
            # Temporal CT issuance bursts; relative window deltas only.
            "deployment_bursts": [
                {
                    "window_start": burst.window_start,
                    "window_end": burst.window_end,
                    "span_seconds": burst.span_seconds,
                    "names": list(burst.names),
                }
                for burst in info.cert_summary.deployment_bursts
            ],
        }
    else:
        d["cert_summary"] = None
    if info.bimi_identity is not None:
        d["bimi_identity"] = {
            "organization": info.bimi_identity.organization,
            "country": info.bimi_identity.country,
            "state": info.bimi_identity.state,
            "locality": info.bimi_identity.locality,
            "trademark": info.bimi_identity.trademark,
        }
    else:
        d["bimi_identity"] = None
    if info.evidence:
        d["evidence"] = [
            {
                "source_type": ev.source_type,
                "raw_value": ev.raw_value,
                "rule_name": ev.rule_name,
                "slug": ev.slug,
            }
            for ev in info.evidence
        ]
    # v2.0 schema contract: always present (empty dict when no detections).
    d["detection_scores"] = dict(info.detection_scores)
    # Cross-source evidence conflicts — top-level array. Always
    # emitted (empty list when none). Each entry is
    # {field, candidates: [{value, source, confidence}, ...]}. The
    # legacy `conflicts` dict under --explain is unchanged for
    # backwards compatibility.
    d["evidence_conflicts"] = serialize_conflicts_array(info.merge_conflicts)
    # Chain motifs — observed CDN/edge → origin shapes from CNAME
    # chain analysis. Always emitted (empty list when none). Each entry
    # is one motif firing on one related subdomain.
    d["chain_motifs"] = [
        {
            "motif_name": cm.motif_name,
            "display_name": cm.display_name,
            "confidence": cm.confidence,
            "subdomain": cm.subdomain,
            "chain": list(cm.chain),
        }
        for cm in info.chain_motifs
    ]
    # Infrastructure clusters — community detection over the CT
    # SAN co-occurrence graph. Always emitted as a stable envelope; the
    # ``algorithm`` field reflects which path produced the partition
    # ("louvain" | "connected_components" | "skipped"). Empty
    # ``clusters`` when no graph could be built.
    if info.infrastructure_clusters is not None:
        ic = info.infrastructure_clusters
        d["infrastructure_clusters"] = {
            "algorithm": ic.algorithm,
            "modularity": ic.modularity,
            # 2.2.0 (schema-additive): partition consensus across a Louvain
            # seed sweep (mean pairwise adjusted Rand index; CAL11). null
            # outside the Louvain path, where the partition is deterministic
            # and the measure is not applicable.
            "partition_stability": ic.partition_stability,
            "stability_runs": ic.stability_runs,
            "node_count": ic.node_count,
            "edge_count": ic.edge_count,
            "clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "size": c.size,
                    "members": list(c.members),
                    "shared_cert_count": c.shared_cert_count,
                    "dominant_issuer": c.dominant_issuer,
                }
                for c in ic.clusters
            ],
        }
    else:
        d["infrastructure_clusters"] = {
            "algorithm": "skipped",
            "modularity": 0.0,
            "partition_stability": None,
            "stability_runs": 0,
            "node_count": 0,
            "edge_count": 0,
            "clusters": [],
        }
    # Note: ``edges`` from the InfrastructureClusterReport is intentionally
    # NOT serialized into the default --json envelope. Raw edges can run
    # into the thousands on heavy targets and would balloon the contract.
    # They surface only via the MCP ``export_graph`` tool, which is the
    # explicit consumer path for graph-rendering pipelines.

    # Per-slug relationship metadata. Always emitted; entries
    # appear only for slugs that fired AND have at least one populated
    # field. Empty object when no detected slug carries metadata. Drives
    # the ecosystem hypergraph and downstream display logic — never
    # an ownership claim, just descriptive hints from the fingerprint
    # YAML.
    metadata_lookup = slug_to_relationship_metadata()
    detected_slug_set = set(info.slugs)
    fingerprint_metadata: dict[str, dict[str, str | None]] = {}
    for slug in sorted(detected_slug_set):
        meta = metadata_lookup.get(slug)
        if meta is None:
            continue
        # Skip entries where every field is None.
        if all(v is None for v in meta.values()):
            continue
        fingerprint_metadata[slug] = meta
    d["fingerprint_metadata"] = fingerprint_metadata
    # External surface attributions — per-subdomain SaaS attribution
    # from CNAME chain classification. Always emitted (empty list when none).
    d["surface_attributions"] = [
        {
            "subdomain": sa.subdomain,
            "primary_slug": sa.primary_slug,
            "primary_name": sa.primary_name,
            "primary_tier": sa.primary_tier,
            "infra_slug": sa.infra_slug,
            "infra_name": sa.infra_name,
        }
        for sa in info.surface_attributions
    ]
    # Opt-in unclassified-chain emission. Off by default keeps the
    # schema narrow; on for the fingerprint-discovery loop.
    if include_unclassified:
        d["unclassified_cname_chains"] = [
            {"subdomain": uc.subdomain, "chain": list(uc.chain)} for uc in info.unclassified_cname_chains
        ]
    # SH6: disambiguate "fusion off" from "fusion ran, found none". The Bayesian
    # layer always emits its nine node posteriors when it runs, so a non-empty
    # posterior_observations means fusion was computed (slug_confidences /
    # posterior_observations being empty then means "off", not "no signal").
    d["fusion_enabled"] = bool(info.posterior_observations)
    # SH7: self-describing payload. record_type discriminates the four object
    # output modes for a consumer (such as an agent) handed a bare payload
    # without the invocation context; schema_version lets a detached payload be
    # routed across a future 2.x to 3.0 boundary.
    d["schema_version"] = "2.0"
    d["record_type"] = "lookup"
    return d


def format_tenant_json(info: TenantInfo, *, include_unclassified: bool = False) -> str:
    """Format TenantInfo as a JSON string."""
    return json.dumps(format_tenant_dict(info, include_unclassified=include_unclassified), indent=2)


def plain_lines(value: Any, key: str, indent: int) -> list[str]:
    """Render one (key, value) as linear, indented `key: value` lines.

    Recurses into dicts and lists. No color, no box-drawing, no markup — a
    greppable, screen-reader-friendly serialization. Strings are control-char
    stripped (the same untrusted-content discipline the panel/markdown sinks
    use); empty/None values are omitted to keep the output scannable.
    """
    pad = "  " * indent
    if value is None or value == "" or value == [] or value == {}:
        return []
    if isinstance(value, dict):
        children: list[str] = []
        for k, v in value.items():
            children.extend(plain_lines(v, str(k), indent + 1))
        return [f"{pad}{key}:", *children] if children else []
    if isinstance(value, list):
        children = []
        for item in value:
            if isinstance(item, dict | list):
                children.extend(plain_lines(item, "-", indent + 1))
            else:
                children.append(f"{pad}  - {strip_control_chars(str(item))}")
        return [f"{pad}{key}:", *children] if children else []
    return [f"{pad}{key}: {strip_control_chars(str(value))}"]


def format_tenant_plain(info: TenantInfo, *, include_unclassified: bool = False) -> str:
    """Format TenantInfo as plain, linear, greppable text (no Rich panel).

    Built from the same dict as the JSON output, so it carries every field the
    structured output does — but as ``key: value`` lines a screen reader reads
    linearly and ``grep``/``awk`` can slice, with no color or box-drawing. This
    is the accessibility / scripting complement to the default panel.
    """
    data = format_tenant_dict(info, include_unclassified=include_unclassified)
    lines: list[str] = []
    for key, value in data.items():
        lines.extend(plain_lines(value, str(key), 0))
    return "\n".join(lines)
# ── CSV output ───────────────────────────────────────────────────────────

CSV_COLUMNS: tuple[str, ...] = (
    "domain",
    "provider",
    "display_name",
    "tenant_id",
    "auth_type",
    "confidence",
    "email_security_score",
    "service_count",
    "dmarc_policy",
    "mta_sts_mode",
    "google_auth_type",
)


_CSV_FORMULA_PREFIXES = frozenset(("=", "+", "-", "@", "\t", "\r", "\n"))


def _csv_safe(value: str) -> str:
    """Neutralize CSV formula-injection prefixes.

    Spreadsheet applications (Excel, LibreOffice, Google Sheets)
    interpret cells starting with ``=``, ``+``, ``-``, ``@``, ``\\t``,
    ``\\r``, or ``\\n`` as formulas. Some import paths also trim
    leading spaces before formula detection. ``display_name`` comes from the
    GetUserRealm ``FederationBrandName`` response, which is
    attacker-controllable for any domain the user chooses to
    look up. A tenant name like ``=HYPERLINK("http://...")`` would
    execute on open.

    Neutralization strategy: prefix the value with a single quote so
    the spreadsheet treats the cell as literal text. The quote is
    visible in the cell but not in the underlying data consumers
    doing machine parsing — those should use the ``--json`` output
    anyway; ``--csv`` is explicitly the human-spreadsheet path.
    """
    if not value:
        return value
    candidate = value.lstrip(" ")
    if candidate and candidate[0] in _CSV_FORMULA_PREFIXES:
        return "'" + value
    return value


def format_tenant_csv_row(info: TenantInfo) -> dict[str, str]:
    """Build a dict of CSV column values for a single TenantInfo.

    Every textual field passes through ``_csv_safe`` so a malicious
    ``FederationBrandName`` (or any other attacker-influenced field)
    can't execute as a formula when the CSV is opened in a spreadsheet.
    """
    provider = detect_provider(info.services, info.slugs)
    return {
        "domain": _csv_safe(info.queried_domain),
        "provider": _csv_safe(provider),
        "display_name": _csv_safe(info.display_name),
        "tenant_id": _csv_safe(info.tenant_id or ""),
        "auth_type": _csv_safe(info.auth_type or ""),
        "confidence": info.confidence.value,
        "email_security_score": str(compute_email_security_score(info)),
        "service_count": str(len(info.services)),
        "dmarc_policy": _csv_safe(info.dmarc_policy or ""),
        "mta_sts_mode": _csv_safe(info.mta_sts_mode or ""),
        "google_auth_type": _csv_safe(info.google_auth_type or ""),
    }


def format_batch_csv(infos: list[tuple[str, TenantInfo | None, str | None]]) -> str:
    """Format a list of (domain, info_or_none, error_or_none) as RFC 4180 CSV.

    Returns a string with header row + one data row per domain.
    """
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)

    for domain, info, _error in infos:
        if info is not None:
            row_dict = format_tenant_csv_row(info)
            writer.writerow([_csv_safe(row_dict[col]) for col in CSV_COLUMNS])
        else:
            # Error row: domain + empty fields
            row = [_csv_safe(domain)] + [""] * (len(CSV_COLUMNS) - 1)
            writer.writerow(row)

    return buf.getvalue()




