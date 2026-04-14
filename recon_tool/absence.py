"""Negative-space analysis — absence signal evaluation.

Pure functions that consume fired signals and detected slugs, producing
absence SignalMatch instances when expected counterpart services are not
observed.

This is the third evaluation pass, running after the two-pass signal
evaluation in signals.py. It reads the ``expected_counterparts`` field
on Signal definitions and checks which counterpart slugs are absent
from the detected set.

All generated text uses defensive, hedged language ("not observed",
"may indicate") rather than assertive claims.
"""

from __future__ import annotations

from recon_tool.signals import Signal, SignalMatch

__all__ = [
    "evaluate_absence_signals",
]

# Slug → human-readable description for absence messages.
# Used to produce hedged, descriptive absence signal text.
_SLUG_DESCRIPTIONS: dict[str, str] = {
    "jamf": "Mac device management (Jamf)",
    "kandji": "Mac device management (Kandji)",
    "crowdstrike": "endpoint security (CrowdStrike)",
    "sentinelone": "endpoint security (SentinelOne)",
    "proofpoint": "email gateway (Proofpoint)",
    "mimecast": "email gateway (Mimecast)",
    "barracuda": "email gateway (Barracuda)",
    "trendmicro": "email gateway (Trend Micro)",
    "lakera": "AI guardrails (Lakera)",
    "okta": "identity provider (Okta)",
    "cyberark": "privileged access (CyberArk)",
    "beyond-identity": "passwordless identity (Beyond Identity)",
    "cosign-attestation": "supply chain attestation (Cosign)",
    "snyk": "dependency security (Snyk)",
}


def _describe_slug(slug: str) -> str:
    """Return a human-readable description for a slug, or the slug itself."""
    return _SLUG_DESCRIPTIONS.get(slug, slug)


def evaluate_absence_signals(
    fired_signals: list[SignalMatch],
    all_signals: tuple[Signal, ...],
    detected_slugs: frozenset[str],
) -> list[SignalMatch]:
    """Third-pass absence evaluation.

    For each signal that fired in passes 1-2 and has non-empty
    ``expected_counterparts``, check which counterpart slugs are absent
    from ``detected_slugs``. Produce an absence SignalMatch for each
    signal with missing counterparts.

    Args:
        fired_signals: Signals that fired in the two-pass evaluation.
        all_signals: All loaded signal definitions (for expected_counterparts lookup).
        detected_slugs: The full set of detected fingerprint slugs.

    Returns:
        List of absence SignalMatch instances with ``category="Absence"``.
    """
    # Build name → Signal lookup for expected_counterparts access
    signal_by_name: dict[str, Signal] = {s.name: s for s in all_signals}

    absence_signals: list[SignalMatch] = []
    for match in fired_signals:
        signal_def = signal_by_name.get(match.name)
        if signal_def is None or not signal_def.expected_counterparts:
            continue

        missing = [slug for slug in signal_def.expected_counterparts if slug not in detected_slugs]
        if not missing:
            continue

        missing_descriptions = ", ".join(_describe_slug(s) for s in missing)
        description = (
            f"{match.name} detected but {missing_descriptions} "
            f"not observed \u2014 may indicate a gap in the expected deployment"
        )

        absence_signals.append(
            SignalMatch(
                name=f"{match.name} \u2014 Missing Counterparts",
                category="Absence",
                confidence="medium",
                matched=tuple(missing),
                description=description,
            )
        )

    return absence_signals
