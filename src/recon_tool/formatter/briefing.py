"""What the default briefing shows, and what it cuts.

The default view is a briefing, not a dump: it names the high-signal related
domains and caps insights, then says how much it withheld. Those rules used to
live inside ``panel.py``, so the linear ``--plain`` renderer (ADR-0016) had no
way to make the same cut and reproduced the whole list instead. A rich record
then read as a briefing in the panel and as a hostname roll call for a screen
reader, which is the surface with the fewest alternatives.

Keeping the rules here gives the two renderers one definition to share. Pure:
no Rich, no rendering, no formatter-facade imports.
"""

from __future__ import annotations

from dataclasses import dataclass

from recon_tool.models import ConfidenceLevel, TenantInfo

__all__ = [
    "SCALE_GAP_NOTE",
    "BriefingView",
    "briefing_insights",
    "build_briefing",
    "cap_insights",
    "high_signal_related",
    "scales_disagree",
]


@dataclass(frozen=True)
class BriefingView:
    """The default view as data, so every renderer shows the same briefing.

    The selection helpers below were already shared by the panel and ``--plain``,
    but ``--md`` and the MCP text surface reached past them and rendered the
    whole record. This is the single object those surfaces consume, so a renderer
    cannot show the default view without making the same cuts. It carries data,
    not formatted lines: each renderer keeps its own wording (the panel counts
    withheld insights against its curated ``--full``, the linear surfaces count
    against the record, ADR-0016 second amendment), and reads the numbers here.

    ``mail`` / ``identity`` are present only on a role split (ADR-0015); off a
    split the caller renders the single ``provider`` row. ``provider_on_split``
    is the role-tagged provider line the linear surfaces keep after the roles so
    a ``grep provider:`` still matches and the repeat carries a reason.
    """

    is_split: bool
    mail: str | None
    mail_detailed: str | None
    identity: str | None
    provider: str
    provider_detailed: str
    provider_on_split: str | None
    related_shown: tuple[str, ...]
    related_total: int
    insights_display: tuple[str, ...]
    insights_curated_overflow: int
    insights_record_total: int
    confidence_tier: str
    source_count: int

    @property
    def related_note(self) -> str | None:
        """Remainder note for a linear surface, naming its own ``--full``."""
        withheld = self.related_total - len(self.related_shown)
        if withheld <= 0:
            return None
        return f"{self.related_total} total, {withheld} more, use --plain --full to see all"

    @property
    def insights_note(self) -> str | None:
        """Withheld-insight note for a linear surface, counted against the record."""
        withheld = self.insights_record_total - len(self.insights_display)
        if withheld <= 0:
            return None
        return f"{withheld} more, use --plain --full to see all"


def build_briefing(info: TenantInfo, *, confidence_mode: str, detailed: bool) -> BriefingView:
    """Compose the shared selection helpers into one default-view object.

    Pure composition of ``role_split_vendors``, ``provider_line``,
    ``high_signal_related``, ``briefing_insights``, and ``cap_insights``, so the
    output is identical to the panel and ``--plain`` computing them inline. The
    classification and role helpers are imported function-locally because they
    pull in ``classify`` (heavy) and this module stays import-light for the pure
    helpers above.

    The briefing always caps insights: a briefing is the capped view by
    definition, and the surfaces that show everything (the panel under
    ``--verbose``/``--full``, ``--plain --full``) render the full list without
    this object rather than by asking it not to cut. ``detailed`` controls only
    the role labels: the expanded linear views (``--plain --verbose`` /
    ``--explain``) keep the evidence-role qualifiers ADR-0012 compacts out of the
    default, while still making the same cuts.
    """
    from recon_tool.formatter.classify import compact_provider_line
    from recon_tool.formatter.roles import role_split_vendors

    split = role_split_vendors(info)
    provider_detailed = split[0] if split is not None else provider_line_of(info)
    mail_detailed = split[0] if split is not None else None
    identity = split[1] if split is not None else None

    related_shown, related_total = high_signal_related(tuple(info.related_domains)) if info.related_domains else ((), 0)

    insights_display: tuple[str, ...] = ()
    curated_overflow = 0
    record_total = len(info.insights)
    if info.insights:
        score_line, ordered = briefing_insights(info, confidence_mode)
        shown, curated_overflow = cap_insights(ordered, verbose=False)
        insights_display = tuple(([score_line] if score_line is not None else []) + shown)

    def _label(detailed_form: str) -> str:
        return detailed_form if detailed else compact_provider_line(detailed_form)

    return BriefingView(
        is_split=split is not None,
        mail=_label(mail_detailed) if mail_detailed is not None else None,
        mail_detailed=mail_detailed,
        identity=identity,
        provider=_label(provider_detailed),
        provider_detailed=provider_detailed,
        provider_on_split=provider_detailed if split is not None else None,
        related_shown=tuple(related_shown),
        related_total=related_total,
        insights_display=insights_display,
        insights_curated_overflow=curated_overflow,
        insights_record_total=record_total,
        confidence_tier=info.confidence.value,
        source_count=len(info.sources),
    )


def provider_line_of(info: TenantInfo) -> str:
    """Local indirection to ``classify.provider_line`` without a module import."""
    from recon_tool.formatter.classify import provider_line

    return provider_line(info)

# High-signal subdomain prefixes for compact related-domain display.
# Tuned to match the UI goal: the related line should fit in 1-2
# lines and show the names a security analyst cares about first.
_HIGH_SIGNAL_RELATED_PREFIXES: tuple[str, ...] = (
    "login.",
    "sso.",
    "auth.",
    "idp.",
    "api.",
    "admin.",
    "portal.",
    "dashboard.",
    "support.",
    "status.",
    "app.",
    "cdn.",
)

_RELATED_DISPLAY_LIMIT = 8
_INSIGHT_DISPLAY_LIMIT = 5

_SPARSE_INSIGHT_PREFIXES = (
    "Sparse public signal:",
    "Sparse public signal \N{EM DASH}",
    "Next step:",
    "Next step \N{EM DASH}",
)


def _is_sparse_insight(line: str) -> bool:
    """Return True when an insight line is part of sparse-result diagnosis."""
    return line.startswith(_SPARSE_INSIGHT_PREFIXES)


def high_signal_related(
    related: tuple[str, ...],
    limit: int = _RELATED_DISPLAY_LIMIT,
) -> tuple[list[str], int]:
    """Pick the top ``limit`` high-signal related domains.

    High-signal = matches one of the ``_HIGH_SIGNAL_RELATED_PREFIXES``.
    Falls back to the first ``limit`` non-wildcard entries when too
    few high-signal names are present. Returns a tuple of
    ``(picked, total_count)`` so callers can emit the "N total" footer.

    ``total_count`` counts every entry the caller passed in, including the ones
    the selection skips. Both renderers point at ``--full`` for the remainder
    and both print the unfiltered list there, so counting only the candidates
    would state a total the reader cannot reach.

    ``*.onmicrosoft.com`` entries are filtered out.
    These are Microsoft 365 tenant artefacts - they appear in the
    related list because the user realm / autodiscover path surfaces
    them, but they carry no "related brand" signal. A CISO reading
    "high-signal related domains" doesn't want to see the tenant's
    own internal domain listed as if it were a separate discovery.
    """

    def _is_high_signal_candidate(d: str) -> bool:
        # Filter out tenant artefacts and wildcards
        if "*" in d:
            return False
        # .onmicrosoft.com and .onmicrosoft.us are M365 tenant
        # artefacts, not brand-related domains worth surfacing.
        return not d.endswith((".onmicrosoft.com", ".onmicrosoft.us"))

    non_wild = [d for d in related if _is_high_signal_candidate(d)]
    total = len(related)
    high: list[str] = []
    for d in non_wild:
        first_label = d.split(".", 1)[0] + "."
        if any(d.startswith(pfx) or first_label == pfx for pfx in _HIGH_SIGNAL_RELATED_PREFIXES):
            high.append(d)
        if len(high) >= limit:
            break
    if len(high) < limit:
        for d in non_wild:
            if d in high:
                continue
            high.append(d)
            if len(high) >= limit:
                break
    return high, total


def briefing_insights(info: TenantInfo, confidence_mode: str) -> tuple[str | None, list[str]]:
    """Return ``(email_security_line, ordered_rest)`` for the default view.

    Curation, strict-mode hedging, and ordering in one place: the email-security
    score is promoted out of the list because the panel renders it first and in
    bold, and sparse-context lines lead the remainder so a thin record explains
    itself before it elaborates.
    """
    from recon_tool.formatter.insight_curation import curate_insights
    from recon_tool.strict_mode import apply_strict_mode, should_apply_strict

    curated = curate_insights(info.insights)
    if should_apply_strict(info, confidence_mode):
        curated = list(apply_strict_mode(tuple(curated)))

    score_line: str | None = None
    sparse: list[str] = []
    other: list[str] = []
    for line in curated:
        if line.startswith("Email security ") and score_line is None:
            score_line = line
        elif _is_sparse_insight(line):
            sparse.append(line)
        else:
            other.append(line)
    return score_line, sparse + other


def cap_insights(ordered: list[str], verbose: bool) -> tuple[list[str], int]:
    """Cap the insight list for the default view; ``verbose`` shows all.

    Returns ``(displayed, withheld_count)`` so the caller can say how many it
    is not showing rather than silently truncating.
    """
    if verbose or len(ordered) <= _INSIGHT_DISPLAY_LIMIT:
        return ordered, 0
    return ordered[:_INSIGHT_DISPLAY_LIMIT], len(ordered) - _INSIGHT_DISPLAY_LIMIT


# ── Confidence vs model support ─────────────────────────────────────────────

_CONFIDENCE_FILL: dict[ConfidenceLevel, int] = {
    ConfidenceLevel.HIGH: 3,
    ConfidenceLevel.MEDIUM: 2,
    ConfidenceLevel.LOW: 1,
}

# Printed when the two dot scales sit two steps apart. They measure different
# things - Confidence counts corroborating sources, Model support is
# threshold-relative - so a Low record carrying a full model display is correct
# and reads as a contradiction to anyone meeting both rows for the first time.
SCALE_GAP_NOTE = "Different questions: source count vs model threshold."

# One step apart is ordinary and needs no gloss; two is the jarring case a
# reader cannot resolve from the rows alone.
_SCALE_GAP_THRESHOLD = 2


def scales_disagree(level: ConfidenceLevel, support_fill: int) -> bool:
    """Whether the two dot scales sit far enough apart to need the gloss."""
    return abs(_CONFIDENCE_FILL[level] - support_fill) >= _SCALE_GAP_THRESHOLD
