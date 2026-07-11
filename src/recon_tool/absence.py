"""Negative-space analysis — absence signal evaluation.

Pure functions that consume fired signals and detected slugs, producing
absence SignalMatch instances when expected counterpart services or a
configured comparison set are not observed.

This is the third evaluation pass, running after the two-pass signal
evaluation in signals.py. Two distinct modes:

1. *Missing counterpart* (existing since v0.9.0) — reads the
   ``expected_counterparts`` field on Signal definitions and emits a
   hedged "X detected but Y not observed" absence signal when any of the
   expected slugs are missing. Category: ``"Absence"``.

2. *Configured comparison absence* (legacy field name
   ``positive_when_absent``) reports only that a signal fired while none of
   its configured comparison indicators were observed. Built-in rules do not
   use this feature because collection opportunity for a generic comparison
   set is not represented in the signal context.

All generated text uses defensive, hedged language. The absence engine
never produces a confident verdict — that is the load-bearing invariant
enforced by the v0.9.3 property-based hedging harness.
"""

from __future__ import annotations

from recon_tool.signals import Signal, SignalMatch

__all__ = [
    "evaluate_absence_signals",
    "evaluate_positive_absence",
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


def evaluate_positive_absence(
    fired_signals: list[SignalMatch],
    all_signals: tuple[Signal, ...],
    detected_slugs: frozenset[str],
) -> list[SignalMatch]:
    """Report a configured comparison set that was not observed.

    Third-pass sibling of :func:`evaluate_absence_signals`. For each fired
    signal with non-empty ``positive_when_absent`` where none of those
    slugs are in ``detected_slugs``, produce one hedged
    derived ``SignalMatch``. The observation does not infer hardening,
    organizational intent, company size, or target type.

    Args:
        fired_signals: Signals that fired in the two-pass evaluation.
        all_signals: All loaded signal definitions (for
            ``positive_when_absent`` lookup).
        detected_slugs: The full set of detected fingerprint slugs.

    Returns:
        List of low-confidence absence observations.
    """
    signal_by_name: dict[str, Signal] = {s.name: s for s in all_signals}

    observations: list[SignalMatch] = []
    for match in fired_signals:
        signal_def = signal_by_name.get(match.name)
        if signal_def is None or not signal_def.positive_when_absent:
            continue

        # Only fire when NONE of the listed slugs are present. Any one
        # of them is enough to disqualify the absence observation.
        if any(slug in detected_slugs for slug in signal_def.positive_when_absent):
            continue

        description = (
            f"{match.name} fired while none of its configured comparison "
            "indicators were observed. This is a bounded non-observation "
            "under current collection coverage and does not establish "
            "configuration, intent, company size, or target type."
        )

        observations.append(
            SignalMatch(
                name=f"{match.name}: Configured Indicators Not Observed",
                category="Absence",
                confidence="low",
                matched=(),
                description=description,
            )
        )

    return observations
