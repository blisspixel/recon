"""Derived connection map: grouped vendors and related-host classes.

Built at format time from TenantInfo plus the fingerprint catalog. Not stored
on the dataclass and not a new collection. Empty lanes stay visible on the
machine face: no match in a lane is unresolved, not proof a product is unused.
"""

from __future__ import annotations

from typing import Any

from recon_tool.fingerprints import load_fingerprints
from recon_tool.formatter.classify import (
    SERVICE_CATEGORIES_ORDER,
    categorize_services,
    service_label_parts,
)
from recon_tool.formatter.classify_tables import SLUG_DISPLAY_OVERRIDES
from recon_tool.models import SurfaceAttribution, TenantInfo

__all__ = [
    "HOST_CLASS_PREFIXES",
    "OTHER_HOST_CLASS",
    "build_connection_map",
    "entry_role",
    "host_class_prefix",
    "lane_id",
    "name_to_slug",
    "related_host_classes",
    "slug_for_name",
    "summaries_by_slug",
    "summary_for_role",
]

# First-label classes a support bot can route on. Longer prefixes first so
# loyalty- wins over a later catch-all. High-signal briefing prefixes are
# included; extras are the ticket-routing labels the max-insight redo named.
HOST_CLASS_PREFIXES: tuple[str, ...] = (
    "loyalty-",
    "community-",
    "rewards.",
    "accounts.",
    "adfs.",
    "login.",
    "sso.",
    "auth.",
    "idp.",
    "api.",
    "admin.",
    "portal.",
    "dashboard.",
    "developer.",
    "support.",
    "status.",
    "help.",
    "shop.",
    "merch.",
    "store.",
    "workday.",
    "careers.",
    "surveys-",
    "vault.",
    "docs.",
    "app.",
    "cdn.",
)
OTHER_HOST_CLASS = "other."

UNAVAILABLE_ROLE = "unavailable"
OBSERVED_CONTROL_ROLE = "observed control"
_ROLE_DETECTION_TYPES: dict[str, tuple[str, ...]] = {
    "public TXT account indicator": ("txt", "subdomain_txt"),
    "MX delivery path": ("mx",),
    "CNAME endpoint binding": ("cname", "cname_target"),
    "SPF sender authorization": ("spf",),
    "DMARC aggregate-report destination": ("dmarc_rua",),
    "SRV service-discovery reference": ("srv",),
    "authoritative DNS delegation": ("ns",),
    "DKIM selector indicator": ("txt",),
    "address endpoint indicator": ("a",),
    "identity endpoint": ("txt", "cname", "cname_target"),
}


def lane_id(label: str) -> str:
    """Stable machine id for a display lane (``Data & Analytics`` -> ``data-analytics``)."""
    lowered = label.lower().replace("&", " ").replace("_", " ")
    parts = [part for part in lowered.split() if part]
    return "-".join(parts)


def first_sentence(text: str) -> str:
    """Return the first sentence of a catalog description, or empty."""
    cleaned = " ".join(text.split())
    if not cleaned:
        return ""
    for index, char in enumerate(cleaned):
        if char == "." and (index + 1 == len(cleaned) or cleaned[index + 1] == " "):
            return cleaned[: index + 1]
    return cleaned


def summaries_by_slug() -> dict[str, list[tuple[str, str]]]:
    """Catalog glosses keyed by slug: ``[(detection_type, first_sentence), ...]``.

    One slug can appear in more than one YAML file. Keep every typed
    description so an MX Microsoft 365 row does not inherit a niche CNAME
    gloss from a later file.
    """
    out: dict[str, list[tuple[str, str]]] = {}
    for fingerprint in load_fingerprints():
        rows = out.setdefault(fingerprint.slug, [])
        seen = {item[0] for item in rows}
        for detection in fingerprint.detections:
            sentence = first_sentence(detection.description)
            if not sentence or detection.type in seen:
                continue
            rows.append((detection.type, sentence))
            seen.add(detection.type)
    return out


def summary_for_role(slug: str | None, role: str, catalog: dict[str, list[tuple[str, str]]]) -> str:
    """Pick the gloss whose detection type matches the evidence role."""
    if not slug:
        return ""
    rows = catalog.get(slug, [])
    if not rows:
        return ""
    preferred = _ROLE_DETECTION_TYPES.get(role, ("txt", "mx"))
    by_type = dict(rows)
    for detection_type in preferred:
        sentence = by_type.get(detection_type)
        if sentence:
            return sentence
    return rows[0][1]


def name_to_slug() -> dict[str, str]:
    """Fingerprint display name and display-override name -> slug."""
    mapping = {fingerprint.name: fingerprint.slug for fingerprint in load_fingerprints()}
    for slug, name in SLUG_DISPLAY_OVERRIDES.items():
        mapping.setdefault(name, slug)
    return mapping


def entry_role(label: str) -> tuple[str, str]:
    """Return ``(name, role)`` for one categorized service label."""
    name, role = service_label_parts(label)
    if role == "role unavailable":
        return name, UNAVAILABLE_ROLE
    if role is not None:
        return name, role
    return name, OBSERVED_CONTROL_ROLE


def slug_for_name(name: str, lookup: dict[str, str] | None = None) -> str | None:
    """Resolve a display name to a catalog slug, including module prefixes."""
    mapping = name_to_slug() if lookup is None else lookup
    if name in mapping:
        return mapping[name]
    for prefix in ("Google Workspace: ", "Microsoft 365: "):
        if name.startswith(prefix):
            return mapping.get(name[: len(prefix) - 2])
    return None


def hosts_by_slug(attributions: tuple[SurfaceAttribution, ...]) -> dict[str, list[str]]:
    """Group attributed subdomains by primary slug, preserving first-seen order."""
    by_slug: dict[str, list[str]] = {}
    for attribution in attributions:
        hosts = by_slug.setdefault(attribution.primary_slug, [])
        if attribution.subdomain not in hosts:
            hosts.append(attribution.subdomain)
    return by_slug


def _lane_entries(
    labels: list[str],
    *,
    lookup: dict[str, str],
    summaries: dict[str, list[tuple[str, str]]],
    hosts: dict[str, list[str]],
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for label in labels:
        name, role = entry_role(label)
        slug = slug_for_name(name, lookup)
        entry: dict[str, Any] = {
            "name": name,
            "slug": slug,
            "role": role,
            "hosts": list(hosts.get(slug, [])) if slug else [],
        }
        summary = summary_for_role(slug, role, summaries)
        if summary:
            entry["summary"] = summary
        entries.append(entry)
    return entries


def host_class_prefix(host: str) -> str:
    """Return the routing class for one related host, or ``other.``."""
    first_label = host.split(".", 1)[0]
    for prefix in HOST_CLASS_PREFIXES:
        if host.startswith(prefix):
            return prefix
        if prefix.endswith("-") and first_label.startswith(prefix):
            return prefix
        if prefix.endswith(".") and first_label == prefix[:-1]:
            return prefix
    return OTHER_HOST_CLASS


def related_host_classes(
    related: tuple[str, ...],
    attributions: tuple[SurfaceAttribution, ...],
) -> list[dict[str, Any]]:
    """Group every related host by first-label class, keeping all names."""
    slugs_by_host: dict[str, list[str]] = {}
    for attribution in attributions:
        slugs = slugs_by_host.setdefault(attribution.subdomain, [])
        if attribution.primary_slug not in slugs:
            slugs.append(attribution.primary_slug)
    grouped: dict[str, list[str]] = {}
    for host in related:
        grouped.setdefault(host_class_prefix(host), []).append(host)
    classes: list[dict[str, Any]] = []
    for prefix in (*HOST_CLASS_PREFIXES, OTHER_HOST_CLASS):
        hosts = grouped.get(prefix)
        if not hosts:
            continue
        primary_slugs: list[str] = []
        for host in hosts:
            for slug in slugs_by_host.get(host, ()):
                if slug not in primary_slugs:
                    primary_slugs.append(slug)
        classes.append({"prefix": prefix, "hosts": hosts, "primary_slugs": primary_slugs})
    return classes


def explicit_absences(info: TenantInfo) -> dict[str, str | None]:
    """JSON fields the briefing hides: gateway and MTA-STS mode, null stays null."""
    from recon_tool.collection_view import collection_observable_evidence
    from recon_tool.merger import compute_email_topology

    _primary, email_gateway, _likely = compute_email_topology(collection_observable_evidence(info))
    return {
        "email_gateway": email_gateway,
        "mta_sts_mode": info.mta_sts_mode,
    }


def build_connection_map(info: TenantInfo) -> dict[str, Any]:
    """Group every observed vendor and related-host class into lanes.

    Always returns every display lane in ``SERVICE_CATEGORIES_ORDER``, including
    empty ``entries`` lists. Role-unavailable matches stay. Does not invent
    product absences (no Slack, no Teams) inside a populated lane.
    """
    from recon_tool.collection_view import collection_observable_info

    info = collection_observable_info(info)
    categorized = categorize_services(info)
    lookup = name_to_slug()
    summaries = summaries_by_slug()
    hosts = hosts_by_slug(info.surface_attributions)
    lanes = [
        {
            "id": lane_id(label),
            "label": label,
            "entries": _lane_entries(
                categorized.get(label, []),
                lookup=lookup,
                summaries=summaries,
                hosts=hosts,
            ),
        }
        for label in SERVICE_CATEGORIES_ORDER
    ]
    return {
        "lanes": lanes,
        "related_host_classes": related_host_classes(info.related_domains, info.surface_attributions),
        "explicit_absences": explicit_absences(info),
    }
