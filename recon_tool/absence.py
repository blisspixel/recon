"""Negative-space analysis — absence signal evaluation.

Pure functions that consume fired signals and detected slugs, producing
absence SignalMatch instances when expected counterpart services are not
observed, and hedged positive observations when a signal fires AND a set
of adversary-friendly slugs is absent.

This is the third evaluation pass, running after the two-pass signal
evaluation in signals.py. Two distinct modes:

1. *Missing counterpart* (existing since v0.9.0) — reads the
   ``expected_counterparts`` field on Signal definitions and emits a
   hedged "X detected but Y not observed" absence signal when any of the
   expected slugs are missing. Category: ``"Absence"``.

2. *Positive when absent* (added in v0.9.3) — reads the
   ``positive_when_absent`` field and emits a hedged two-sided positive
   observation when the signal fires AND none of the listed
   consumer-facing / adversary-friendly slugs are detected. Category:
   ``"Hardening Observation"``. The phrasing is deliberately two-sided
   ("fits deliberate hardening or a dormant / parked / small-shop
   target") because the same sparse evidence fits multiple
   interpretations — the output never commits to one reading.

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
    """Emit hedged positive observations when a signal fires AND an
    adversary-friendly slug set is absent.

    Third-pass sibling of :func:`evaluate_absence_signals`. For each fired
    signal with non-empty ``positive_when_absent`` where none of those
    slugs are in ``detected_slugs``, produce one hedged
    ``"Hardening Observation"`` SignalMatch.

    The emitted statement is deliberately two-sided: the same evidence
    (an edge-proxy composite firing without consumer SaaS) fits
    deliberate hardening, a dormant / parked target, or a small shop
    with a proxy in front of very little. The output never commits to
    one reading — it surfaces the observation and enumerates the
    alternative interpretations in the same breath.

    Args:
        fired_signals: Signals that fired in the two-pass evaluation.
        all_signals: All loaded signal definitions (for
            ``positive_when_absent`` lookup).
        detected_slugs: The full set of detected fingerprint slugs.

    Returns:
        List of ``SignalMatch`` instances with
        ``category="Hardening Observation"``.
    """
    signal_by_name: dict[str, Signal] = {s.name: s for s in all_signals}

    observations: list[SignalMatch] = []
    for match in fired_signals:
        signal_def = signal_by_name.get(match.name)
        if signal_def is None or not signal_def.positive_when_absent:
            continue

        # Only fire when NONE of the listed slugs are present. Any one
        # of them is enough to disqualify the hardening reading.
        if any(slug in detected_slugs for slug in signal_def.positive_when_absent):
            continue

        description = (
            f"{match.name} fires without consumer SaaS exposure — "
            "fits a deliberately hardened target, a dormant / parked "
            "domain, or a small shop behind an edge proxy. Hedged "
            "observation, not a verdict."
        )

        observations.append(
            SignalMatch(
                name=f"{match.name} \u2014 Hardening Pattern Observed",
                category="Hardening Observation",
                confidence="low",
                matched=(),
                description=description,
            )
        )

    return observations
