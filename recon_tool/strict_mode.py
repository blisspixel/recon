"""Strict confidence mode — drops hedging qualifiers on dense-evidence targets.

Hedged output ("observed", "likely", "indicators") is the right default because
a passive tool can be wrong. But on a target with High confidence AND 3+
corroborating sources, the hedging becomes noise — a CISO looking at a Fortune
500 tenant with four independent sources doesn't need "observed" and "fits a
pattern" on every line.

Strict mode is opt-in via `--confidence-mode strict`. It only activates when
the evidence is dense enough to justify dropping hedging. Sparse-data output
is unchanged — the invariant "never overclaim when evidence is thin" stays
load-bearing.

This module applies purely lexical transforms to already-generated insight
text. The insight generators in ``insights.py``, ``absence.py``, and
``lexical.py`` continue to emit hedged prose by default; strict mode is a
post-processing pass that never fires on low-density evidence.
"""

from __future__ import annotations

from recon_tool.models import ConfidenceLevel, TenantInfo

__all__ = [
    "STRICT_SOURCE_THRESHOLD",
    "apply_strict_mode",
    "should_apply_strict",
]

# Dense-evidence gate: strict mode only fires when confidence is High AND
# this many distinct sources contributed. Three is the same threshold used
# for ConfidenceLevel.HIGH in the merger pipeline.
STRICT_SOURCE_THRESHOLD = 3


# Ordered transforms. Applied sequentially — earlier transforms can enable
# later ones (e.g. "indicators observed" collapses before the plain
# "indicators" cleanup). Each tuple is (search, replace); plain string
# replacement only — no regex so the transforms are auditable.
_STRICT_TRANSFORMS: tuple[tuple[str, str], ...] = (
    # Remove the "indicators observed (likely ...)" compound qualifier
    (" indicators observed (likely ", " ("),
    (" indicators observed", ""),
    # Strip "indicators" when it appears right before a parenthetical
    (" indicators (", " ("),
    # "(likely X)" → "(X)" — the enclosing context already carries the hedge
    ("(likely ", "("),
    # "(observed ..." → "(..." — the insight text follows the observation
    ("(observed cloud_instance=", "(cloud_instance="),
    # "Likely Azure China" → "Azure China"; "Likely US Government" → "US Government"
    ("Likely Azure China ", "Azure China "),
    ("Likely US Government ", "US Government "),
    # Dangling "observed" at end of common insight phrases
    (" — observed", ""),
    ("(observed)", ""),
)


def should_apply_strict(info: TenantInfo, confidence_mode: str) -> bool:
    """True when strict mode should transform the insight output.

    Gate: user opted into strict mode AND evidence is dense enough
    (High confidence AND at least :data:`STRICT_SOURCE_THRESHOLD`
    distinct sources). Sparse-data output is never touched.
    """
    if confidence_mode != "strict":
        return False
    if info.confidence != ConfidenceLevel.HIGH:
        return False
    return len(info.sources) >= STRICT_SOURCE_THRESHOLD


def apply_strict_mode(insights: tuple[str, ...]) -> tuple[str, ...]:
    """Drop hedging qualifiers from each insight string.

    Only changes textual hedging markers — factual content (score values,
    service names, slug lists) is preserved verbatim. Collapses any
    resulting double spaces so the output still reads cleanly.
    """
    result: list[str] = []
    for original in insights:
        transformed = original
        for search, replace in _STRICT_TRANSFORMS:
            transformed = transformed.replace(search, replace)
        # Collapse double spaces left behind by replacements
        transformed = " ".join(transformed.split())
        result.append(transformed)
    return tuple(result)
