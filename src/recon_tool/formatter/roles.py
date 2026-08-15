"""Evidence-role derivation and claim description for the default view.

Two related jobs that the panel renders but should not decide:

* which vendor holds which **role** on a domain (ADR-0015), derived from
  evidence provenance rather than from a slug's catalog category; and
* how a model-relative claim is **described** without confidence language.

Both are pure. Splitting them out of ``classify`` and ``panel`` keeps those
modules inside their size ceilings and puts the role rules in one place, so a
renderer cannot quietly disagree with the categorizer about what a vendor does.

Imports nothing from the formatter facade and does no Rich rendering. The one
dependency on ``classify.provider_line`` is function-local, because ``classify``
imports this module.
"""

from __future__ import annotations

from recon_tool.models import PosteriorObservation, TenantInfo

__all__ = [
    "DOT_FILL_COLOR",
    "DOT_FILL_GLYPH",
    "TENANT_CLASS_NODES",
    "identity_role_vendors",
    "model_support_claims",
    "posterior_dot_fill",
    "posterior_support_phrase",
    "role_split_vendors",
]

# Rule names emitted by the unauthenticated identity endpoints. A vendor
# observed through one of these has an identity role on this domain, whatever
# category its slug carries in the catalog. Provenance is the discriminator
# here, not CATEGORY_BY_SLUG: that table states what kind of thing a slug
# usually is, not what was observed on the domain in hand. Both microsoft365
# and google-workspace are catalogued under Email, which is exactly why a
# category-driven rule would file a tenant observation as a mail service.
IDENTITY_ENDPOINT_RULES = frozenset(
    {
        "OIDC Discovery",
        "OIDC Discovery metadata",
        "GetUserRealm",
        "Autodiscover",
        "Google Identity Routing",
    }
)

# Nodes that assert "this domain is a tenant of vendor X". Two of these above
# threshold on one record is the case ADR-0015 exists for: naming only one of
# them corroborates a single vendor while a second sits equally supported.
TENANT_CLASS_NODES = frozenset({"m365_tenant", "google_workspace_tenant"})


def identity_role_vendors(info: TenantInfo) -> tuple[str, ...]:
    """Return display names for vendors observed at an identity endpoint.

    ADR-0015. Ordered by first observation so the rendering is deterministic,
    and de-duplicated because one vendor commonly emits several identity
    records (a tenant id, a brand name, a namespace type).

    Empty when the domain published no identity-endpoint evidence, which keeps
    absence absent: a missing identity role must not render as a bare or empty
    row.
    """
    from recon_tool.collection_view import collection_observable_evidence, collection_observable_info
    from recon_tool.fingerprints import load_fingerprints
    from recon_tool.formatter.classify_tables import SLUG_DISPLAY_OVERRIDES

    observable = collection_observable_info(info)
    try:
        slug_to_name = {fp.slug: fp.name for fp in load_fingerprints()}
    except Exception:  # pragma: no cover - catalog load already guarded elsewhere
        slug_to_name = {}

    vendors: list[str] = []
    for evidence in collection_observable_evidence(observable):
        if evidence.rule_name not in IDENTITY_ENDPOINT_RULES or not evidence.slug:
            continue
        name = SLUG_DISPLAY_OVERRIDES.get(evidence.slug) or slug_to_name.get(evidence.slug, evidence.slug)
        if name not in vendors:
            vendors.append(name)
    return tuple(vendors)


def role_split_vendors(info: TenantInfo) -> tuple[str, str] | None:
    """Return ``(mail_label, identity_label)`` when the two roles disagree.

    ADR-0015. Returns None for the ordinary case so the caller keeps rendering
    a single ``Provider`` row: no identity evidence, or an identity vendor the
    mail summary already names. Only a genuine disagreement splits the row, so
    single-vendor panels stay byte-identical to before.
    """
    from recon_tool.formatter.classify import provider_line

    identity = identity_role_vendors(info)
    if not identity:
        return None
    mail = provider_line(info)
    if not mail:
        return None
    # Already named by the mail summary: one vendor doing both jobs is not a
    # split, and printing it twice would imply two findings where there is one.
    if all(vendor in mail for vendor in identity):
        return None
    return mail, ", ".join(identity)


# ── Model-relative claim description ────────────────────────────────────────
#
# Stays distinct from deterministic confidence because the hand-set uncertainty
# band is not calibrated and its width is not generally evidence-monotone.
POSTERIOR_DECISION_THRESHOLD = 0.5

# How a fill level is expressed. Beside the function that computes it so the
# glyph and the threshold rule cannot drift apart; the panel owns placement.
DOT_FILL_GLYPH: dict[int, str] = {3: "●●●", 2: "●●○", 1: "●○○"}
DOT_FILL_COLOR: dict[int, str] = {3: "#a3d9a5", 2: "#7ec8e3", 1: "#e07a5f"}


def posterior_dot_fill(obs: PosteriorObservation, threshold: float = POSTERIOR_DECISION_THRESHOLD) -> int:
    """Solid-dot count (1 to 3) for a positive claim's model display.

    - 3: the whole interval is above the threshold.
    - 2: the point estimate is on the yes-side but the interval dips below the
      threshold, so the display straddles the threshold.
    - 1: the point estimate is on the no-side of the model threshold.

    Pure and monotone in ``interval_low`` then ``posterior``; pinned by a
    property test so the renderer cannot drift or recalibrate through the UI.
    """
    if obs.interval_low >= threshold:
        return 3
    if obs.posterior >= threshold:
        return 2
    return 1


# Human-readable claim name per node for the disagreement clause. Short so the
# dimmed row stays one line; vendor-qualified so "Workspace" names one vendor.
NODE_CLAIM_NAMES: dict[str, str] = {
    "m365_tenant": "the M365 tenant",
    "google_workspace_tenant": "the Google Workspace tenant",
    "federated_identity": "federated identity",
    "okta_idp": "the Okta IdP",
    "email_gateway_present": "the email gateway",
    "email_security_modern_provider": "modern email security",
    "email_security_policy_enforcing": "the email policy",
    "cdn_fronting": "the CDN",
    "aws_hosting": "AWS hosting",
}


def model_support_claims(
    claimed: list[PosteriorObservation],
) -> tuple[list[PosteriorObservation], int]:
    """Return the claims the Model support row should name, and their fill.

    The row reports the **weakest** claimed node, which is the conservative
    reading and stays the source of the dot fill. ADR-0015 adds one rule: when
    several tenant-class claims sit at that same fill, name all of them. Naming
    one vendor while an equally supported second goes unmentioned is the same
    wrong-primary defect the Provider row had.
    """
    weakest = min(claimed, key=lambda o: (posterior_dot_fill(o), o.posterior))
    fill = posterior_dot_fill(weakest)
    peers = [o for o in claimed if o.name in TENANT_CLASS_NODES and posterior_dot_fill(o) == fill]
    return (peers if len(peers) > 1 else [weakest]), fill


def posterior_support_phrase(claims: list[PosteriorObservation], fill: int) -> str:
    """Describe claimed nodes' model display without confidence language."""
    names = [NODE_CLAIM_NAMES.get(obs.name, f"the {obs.name} call") for obs in claims]
    claim = names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"
    if fill >= 3:
        return f"display above threshold for {claim}"
    if fill == 2:
        return f"threshold-straddling display for {claim}"
    return f"model mean below threshold for {claim}"
