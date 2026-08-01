"""Canonical availability semantics for generated-insight observation scopes."""

from __future__ import annotations

from collections.abc import Iterable

from recon_tool.source_status import ObservationChannel, SourceStatus

_SCOPE_CHANNELS: dict[str, tuple[ObservationChannel, ...]] = {
    "dns:mx": ("mx",),
    "dns:apex_txt": ("apex_txt",),
    "dns:cname": ("cname",),
    "dns:dmarc": ("dmarc",),
    "dns:dkim_common_selectors": ("dkim",),
    "http:mta_sts_policy": ("mta_sts",),
    "dns:bimi": ("bimi",),
    "dns:caa": ("caa",),
    "dns:catalog": ("apex_txt", "cname", "subdomain_txt"),
    "public_metadata:service_catalog": (
        "apex_txt",
        "mx",
        "cname",
        "ns",
        "a",
        "caa",
        "srv",
        "subdomain_txt",
    ),
    "dns:bounded_service_records": ("cname", "ns", "a", "srv", "subdomain_txt"),
}

_SCOPE_DEGRADED_MARKERS: dict[str, frozenset[str]] = {
    "identity:user_realm": frozenset({"identity:user_realm", "source:user_realm", "user_realm"}),
    "identity:autodiscover": frozenset({"identity:autodiscover", "source:user_realm", "user_realm"}),
    "identity:oidc_discovery": frozenset({"source:oidc_discovery", "oidc_discovery"}),
    "identity:google_routing": frozenset({"source:google_identity", "google_identity"}),
}

_COMPLETE_COLLECTION_SCOPE = "public_metadata:bounded_collection"

INSIGHT_OBSERVATION_SCOPES = frozenset({*_SCOPE_CHANNELS, *_SCOPE_DEGRADED_MARKERS, _COMPLETE_COLLECTION_SCOPE})


def unavailable_observation_scopes(
    scopes: Iterable[str],
    degraded_sources: Iterable[str],
) -> tuple[str, ...]:
    """Return required scopes made unavailable by one collection result.

    Unknown scope identifiers fail closed. The complete-collection scope is
    used only by sparse-result claims, whose premise is not supportable when
    any collector or detector reports an unavailable opportunity.
    """
    status = SourceStatus.from_degraded_sources(degraded_sources)
    unavailable: list[str] = []
    for scope in scopes:
        channels = _SCOPE_CHANNELS.get(scope)
        markers = _SCOPE_DEGRADED_MARKERS.get(scope)
        if channels is not None:
            is_unavailable = any(status.channel_unavailable(channel) for channel in channels)
        elif markers is not None:
            is_unavailable = not status.degraded_sources.isdisjoint(markers)
        elif scope == _COMPLETE_COLLECTION_SCOPE:
            is_unavailable = bool(status.degraded_sources)
        else:
            is_unavailable = True
        if is_unavailable:
            unavailable.append(scope)
    return tuple(unavailable)


def observation_scopes_available(
    scopes: Iterable[str],
    degraded_sources: Iterable[str],
) -> bool:
    """Return whether every required observation opportunity was available."""
    return not unavailable_observation_scopes(scopes, degraded_sources)
