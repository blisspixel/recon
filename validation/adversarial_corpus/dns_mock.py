"""Thin fixture-authoring helper for the adversarial DNS-record corpus.

``build_source_result`` constructs one ``SourceResult`` carrying only the fields
``replay_cached_dns_fingerprints`` reads: the cached ``raw_dns_records`` plus the
four availability guards (``error``, ``source_unavailable``, ``degraded_sources``
and, implicitly, a present source). It invents no matches and touches no network.
Planting is list concatenation on the record list, so a planted record set is
typed, total, and byte-identical on replay.

``scalar_override`` is the only route by which a non-DNS identity or policy scalar
(``tenant_id``, ``auth_type``, ``google_auth_type``, ``google_idp_name``,
``dmarc_policy``) reaches the assembled ``TenantInfo``. It is forbidden on a
gate-path fixture (the runner asserts the four identity scalars stay ``None``
there) and names exactly the scalar a bypass-path fixture injects, so a transition
is attributable to the plant rather than to a stray scalar.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from recon_tool.models import SourceResult

# Scalars that originate in OIDC / UserRealm / DMARC collection, never in a raw
# apex record. A bare DNS-replay result leaves every one of them unset.
INJECTABLE_SCALARS = ("tenant_id", "auth_type", "google_auth_type", "google_idp_name", "dmarc_policy")
IDENTITY_SCALARS = ("tenant_id", "auth_type", "google_auth_type", "google_idp_name")


def build_source_result(
    queried_domain: str,
    records: list[tuple[str, str]],
    scalar_override: dict[str, str] | None = None,
    source_name: str = "dns-replay-fixture",
) -> SourceResult:
    """Return a ``SourceResult`` that ``replay_cached_dns_fingerprints`` accepts.

    ``queried_domain`` is retained for caller symmetry with the collection API;
    the replay path reads only ``raw_dns_records`` and the availability fields.
    """
    from recon_tool.models import SourceResult

    if scalar_override:
        unknown = set(scalar_override) - set(INJECTABLE_SCALARS)
        if unknown:
            raise ValueError(f"scalar_override names non-injectable field(s): {sorted(unknown)}")
    fields: dict[str, object] = {
        "source_name": source_name,
        "raw_dns_records": tuple((record_type, value) for record_type, value in records),
        "error": None,
        "source_unavailable": False,
        "degraded_sources": (),
    }
    if scalar_override:
        fields.update(scalar_override)
    return SourceResult(**fields)  # pyright: ignore[reportArgumentType]
