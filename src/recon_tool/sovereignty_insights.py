"""Microsoft sovereign-cloud insight generation with field-exact lineage."""

from __future__ import annotations

from typing import Protocol

from recon_tool.insight_claims import InsightEvidenceContext, claim_text
from recon_tool.models import EvidenceRecord
from recon_tool.validator import host_has_suffix


class SovereigntyContext(InsightEvidenceContext, Protocol):
    """OIDC metadata consumed by the sovereignty classifier."""

    @property
    def cloud_instance(self) -> str | None: ...

    @property
    def tenant_region_sub_scope(self) -> str | None: ...

    @property
    def msgraph_host(self) -> str | None: ...


def _metadata_evidence(
    ctx: SovereigntyContext,
    field_names: tuple[str, ...],
) -> tuple[EvidenceRecord, ...]:
    """Select only OIDC metadata fields used by the rendered branch."""
    prefixes = tuple(f"{field_name}=".casefold() for field_name in field_names)
    return tuple(
        record
        for record in ctx.evidence
        if record.rule_name == "OIDC Discovery metadata" and record.raw_value.casefold().startswith(prefixes)
    )


def _observed_details(ctx: SovereigntyContext, field_names: tuple[str, ...]) -> str:
    """Render only metadata fields actually observed and classified."""
    values = {
        "cloud_instance_name": ctx.cloud_instance,
        "tenant_region_sub_scope": ctx.tenant_region_sub_scope,
        "msgraph_host": ctx.msgraph_host,
    }
    return ", ".join(f"{field_name}={values[field_name]}" for field_name in field_names if values[field_name])


def _sovereignty_claim(
    text: str,
    ctx: SovereigntyContext,
    field_names: tuple[str, ...],
) -> str:
    """Associate a scalar OIDC classification with its exact metadata fields."""
    return claim_text(
        text,
        evidence=_metadata_evidence(ctx, field_names),
        scope=("identity:oidc_discovery",),
        allows_scope_only=True,
    )


def sovereignty_insights(ctx: SovereigntyContext) -> list[str]:
    """Surface hedged Microsoft tenant sovereignty observations."""
    cloud_instance = (ctx.cloud_instance or "").lower()
    sub_scope = (ctx.tenant_region_sub_scope or "").strip()
    msgraph_host = (ctx.msgraph_host or "").lower()
    if not cloud_instance and not sub_scope and not msgraph_host:
        return []

    us_fields: list[str] = []
    if host_has_suffix(cloud_instance, "microsoftonline.us"):
        us_fields.append("cloud_instance_name")
    if host_has_suffix(msgraph_host, "graph.microsoft.us"):
        us_fields.append("msgraph_host")
    if us_fields:
        if sub_scope and sub_scope.upper() in ("DOD", "GCCH"):
            us_fields.append("tenant_region_sub_scope")
            text = f"Likely US Government GCC High / DoD tenant (observed {_observed_details(ctx, tuple(us_fields))})"
        else:
            text = (
                "Likely US Government Community Cloud (GCC) tenant "
                f"(observed {_observed_details(ctx, tuple(us_fields))})"
            )
        return [_sovereignty_claim(text, ctx, tuple(us_fields))]

    china_fields: list[str] = []
    if host_has_suffix(cloud_instance, "partner.microsoftonline.cn"):
        china_fields.append("cloud_instance_name")
    if host_has_suffix(msgraph_host, "microsoftgraphchina.cn"):
        china_fields.append("msgraph_host")
    if china_fields:
        fields = tuple(china_fields)
        text = f"Likely Azure China 21Vianet tenant (observed {_observed_details(ctx, fields)})"
        return [_sovereignty_claim(text, ctx, fields)]

    if host_has_suffix(cloud_instance, "b2clogin.com"):
        fields = ("cloud_instance_name",)
        text = f"Azure AD B2C tenant (observed {_observed_details(ctx, fields)})"
        return [_sovereignty_claim(text, ctx, fields)]

    if cloud_instance and not host_has_suffix(cloud_instance, "microsoftonline.com"):
        fields = ("cloud_instance_name",)
        text = f"Non-commercial Microsoft cloud instance observed: {ctx.cloud_instance}"
        return [_sovereignty_claim(text, ctx, fields)]

    return []
