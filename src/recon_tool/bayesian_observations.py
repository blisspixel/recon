"""Claim-scoped observations consumed by the Bayesian network."""

from __future__ import annotations

from collections.abc import Iterable

from recon_tool.constants import effective_dmarc_policy
from recon_tool.source_status import SourceStatus


def _has_evidence(
    evidence: Iterable[object],
    source_types: frozenset[str],
    slugs: frozenset[str],
) -> bool:
    """Return whether one retained record carries the requested role."""
    return any(
        getattr(item, "source_type", "").upper() in source_types and getattr(item, "slug", "") in slugs
        for item in evidence
    )


def _role_observations(info: object, evidence: tuple[object, ...]) -> set[str]:
    """Derive role-specific observations without reusing generic vendor slugs."""
    observed: set[str] = set()
    auth_type = getattr(info, "auth_type", None)
    google_auth_type = getattr(info, "google_auth_type", None)
    google_idp_name = getattr(info, "google_idp_name", None)
    if (
        getattr(info, "tenant_id", None) is not None
        or auth_type in {"Federated", "Managed"}
        or _has_evidence(
            evidence,
            frozenset({"HTTP", "MX", "DKIM", "CNAME", "SRV"}),
            frozenset({"microsoft365", "entra-id", "exchange-online"}),
        )
    ):
        observed.add("m365_tenant_observed")
    if google_auth_type in {"Federated", "Managed"} or _has_evidence(
        evidence,
        frozenset({"HTTP", "MX", "DKIM", "CNAME"}),
        frozenset({"google-workspace", "gmail"}),
    ):
        observed.add("google_workspace_tenant_observed")
    if auth_type == "Federated" or google_auth_type == "Federated":
        observed.add("federated_sso_hub")
    if isinstance(google_idp_name, str) and google_idp_name.casefold() == "okta":
        observed.add("okta_idp_observed")
    if getattr(info, "email_gateway", None) is not None and _has_evidence(
        evidence,
        frozenset({"MX"}),
        frozenset({"proofpoint", "mimecast", "barracuda"}),
    ):
        observed.add("email_gateway_mx_observed")
    if _has_evidence(
        evidence,
        frozenset({"CNAME"}),
        frozenset({"cloudflare", "akamai", "fastly"}),
    ):
        observed.add("cdn_cname_observed")
    if _has_evidence(
        evidence,
        frozenset({"CNAME"}),
        frozenset({"aws", "aws-cloudfront"}),
    ):
        observed.add("aws_endpoint_cname_observed")
    return observed


def signals_from_tenant_info(info: object) -> set[str]:
    """Derive Bayesian observations from already-collected tenant data.

    Provider-role observations require evidence whose record type supports the
    claimed role. Generic verification TXT, NS, CAA, and unrelated vendor
    fingerprints remain inventory observations and cannot satisfy these nodes.
    """
    status = SourceStatus.from_degraded_sources(getattr(info, "degraded_sources", ()) or ())
    evidence = tuple(getattr(info, "evidence", ()) or ())
    observed = _role_observations(info, evidence)

    effective_dmarc = (
        effective_dmarc_policy(
            getattr(info, "dmarc_policy", None),
            getattr(info, "dmarc_pct", None),
            getattr(info, "dmarc_testing", False),
        )
        if status.channel_available("dmarc")
        else None
    )
    if effective_dmarc == "reject":
        observed.add("dmarc_reject")
    elif effective_dmarc == "quarantine":
        observed.add("dmarc_quarantine")
    if status.channel_available("mta_sts") and getattr(info, "mta_sts_mode", None) == "enforce":
        observed.add("mta_sts_enforce")
    if status.channel_available("dkim") and any(
        getattr(item, "source_type", "").upper() == "DKIM" for item in evidence
    ):
        observed.add("dkim_present")
    if status.channel_available("apex_txt") and _has_evidence(
        evidence,
        frozenset({"SPF"}),
        frozenset({"spf-strict"}),
    ):
        observed.add("spf_strict")
    return observed
