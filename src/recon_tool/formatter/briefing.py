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

from recon_tool.models import ConfidenceLevel, TenantInfo

__all__ = [
    "SCALE_GAP_NOTE",
    "briefing_insights",
    "cap_insights",
    "high_signal_related",
    "scales_disagree",
]

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
