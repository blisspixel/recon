"""Evidence-aware derivations for the default panel key-facts block."""

from __future__ import annotations

from recon_tool.collection_view import collection_observable_evidence, collection_observable_info
from recon_tool.formatter.classify import count_cloud_vendors
from recon_tool.models import TenantInfo

__all__ = ["key_facts_auth_line", "key_facts_multicloud_line"]


def _with_idp(base: str, google_idp_name: str | None) -> str:
    """Append a reported Google identity provider to an auth label."""
    return f"{base} via {google_idp_name}" if google_idp_name else base


def key_facts_auth_line(info: TenantInfo) -> str | None:
    """Combine observable Microsoft and Google authentication labels."""
    visible = collection_observable_info(info)
    effective_auth = visible.auth_type
    if effective_auth and effective_auth.strip().lower() == "unknown":
        effective_auth = None

    auth_parts: list[str] = []
    if effective_auth and visible.google_auth_type:
        if effective_auth == visible.google_auth_type:
            microsoft_label = "Entra ID" if "microsoft365" in visible.slugs else "Microsoft"
            providers = [microsoft_label, _with_idp("Google Workspace", visible.google_idp_name)]
            auth_parts.append(f"{effective_auth} ({' + '.join(providers)})")
        else:
            auth_parts.append(effective_auth)
            google_label = _with_idp(visible.google_auth_type, visible.google_idp_name)
            auth_parts.append(f"{google_label} (Google Workspace)")
    elif effective_auth:
        auth_parts.append(effective_auth)
    elif visible.google_auth_type:
        google_label = _with_idp(visible.google_auth_type, visible.google_idp_name)
        auth_parts.append(f"{google_label} (Google Workspace)")
    return " + ".join(auth_parts) or None


def key_facts_multicloud_line(info: TenantInfo) -> str | None:
    """Summarize at least two public workload-provider observations."""
    visible = collection_observable_info(info)
    surface_slugs = [
        slug
        for attribution in visible.surface_attributions
        for slug in (attribution.primary_slug, attribution.infra_slug)
        if slug
    ]
    vendor_counts = count_cloud_vendors(
        visible.slugs,
        surface_slugs,
        apex_evidence=collection_observable_evidence(visible),
    )
    if len(vendor_counts) < 2:
        return None
    ranked = sorted(vendor_counts.items(), key=lambda item: (-item[1], item[0]))
    vendor_names = [vendor for vendor, _ in ranked]
    return f"{len(vendor_names)} providers observed ({', '.join(vendor_names)})"
