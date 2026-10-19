"""The source ladder: per-family collection progress and the source-health line.

While a single-domain lookup collects, stderr can show one row per source
family that settles to matched, no match or unavailable. When collection ends
the rows collapse into one source-health line, which is also the static form
used whenever animation is off. ``cli/source_ladder.py`` decides when to
animate and draws the frames; this module owns the state and the wording.

The state is fed by ``collection_progress`` events and, at the end, by the
resolver's own results, so a lookup whose events were never seen (a cached
or injected resolver) still gets a correct line. Counts are per collection
unit, not per row: a row can group two units (Google identity routing and the
opt-in Google CSE probe).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal, get_args

from rich.text import Text

from recon_tool import collection_progress as progress
from recon_tool.collection_progress import ProgressEvent, UnitOutcome
from recon_tool.confidence import is_confidence_contributor
from recon_tool.formatter import theme
from recon_tool.models import SourceResult
from recon_tool.source_status import ObservationChannel, SourceStatus

__all__ = [
    "FAMILIES",
    "SPINNER_FRAMES",
    "UNIT_LABELS",
    "Family",
    "LadderState",
    "short_reason",
]

SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_ASCII_SPINNER_FRAMES = "|/-\\"
_DNS_UNIT = "dns_records"
_MAX_LISTED_REASONS = 3
_LABEL_WIDTH = 28
_DNS_CHANNEL_COUNT = len(get_args(ObservationChannel))


@dataclass(frozen=True, slots=True)
class Family:
    """One ladder row: a label and the collection units it groups."""

    key: str
    label: str
    units: tuple[str, ...]


FAMILIES: tuple[Family, ...] = (
    Family("dns", "DNS records", (_DNS_UNIT,)),
    Family("microsoft_tenant", "Microsoft tenant discovery", ("oidc_discovery",)),
    Family("microsoft_realm", "Microsoft user realm", ("user_realm",)),
    Family("google", "Google identity", ("google_identity", "google_workspace")),
    Family("mta_sts", "MTA-STS policy", (progress.MTA_STS_UNIT,)),
    Family("ct", "Certificate transparency", (progress.CT_UNIT,)),
)

UNIT_LABELS: dict[str, str] = {
    _DNS_UNIT: "DNS",
    "oidc_discovery": "OIDC discovery",
    "user_realm": "user realm",
    "google_identity": "Google identity",
    "google_workspace": "Google CSE probe",
    progress.MTA_STS_UNIT: "MTA-STS",
    progress.CT_UNIT: "CT",
}

_HTTP_STATUS = re.compile(r"\bHTTP (\d{3})\b")


_REASON_PATTERNS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("could not resolve", "could not be validated"), "could not resolve"),
    (("private address",), "private address skipped"),
    (("dns resolution unavailable",), "no resolver response"),
    (("timed out", "timeout"), "timeout"),
    (("429", "rate limit"), "rate limited"),
)


def short_reason(error: str | None) -> str:
    """Reduce a collector error to a short, fixed-vocabulary reason.

    Collector errors can quote untrusted text (hostnames, response fragments),
    so the ladder never echoes them; it maps them to known phrases instead.
    """
    if not error:
        return "unavailable"
    lower = error.lower()
    for needles, reason in _REASON_PATTERNS:
        if any(needle in lower for needle in needles):
            return reason
    status = _HTTP_STATUS.search(error)
    return f"HTTP {status.group(1)}" if status is not None else "error"


def _result_outcome(result: SourceResult) -> UnitOutcome:
    """Classify a top-level source result.

    Only an explicit ``source_unavailable`` is a failure. A stable negative
    answer that a collector reports in ``error`` (a domain with no Microsoft
    realm, say) is a clean no-match, not an outage.
    """
    if result.source_unavailable:
        return UnitOutcome("unavailable", short_reason(result.error))
    if is_confidence_contributor(result):
        return UnitOutcome("match")
    if result.source_name == _DNS_UNIT:
        # DNS answers some queries and loses others. With nothing matched, a
        # lost channel means the empty answer was not fully observed.
        lost = SourceStatus.from_degraded_sources(result.degraded_sources).unavailable_channels
        if lost:
            return UnitOutcome("unavailable", f"{len(lost)} of {_DNS_CHANNEL_COUNT} record types unavailable")
    return UnitOutcome("no_match")


_Status = Literal["pending", "running"]


class LadderState:
    """Mutable ladder state. Applied on the event loop only, never a thread."""

    def __init__(self, units: Iterable[str]) -> None:
        self._order: list[str] = list(units)
        self._running: dict[str, _Status] = dict.fromkeys(self._order, "pending")
        self._settled: dict[str, UnitOutcome] = {}

    @classmethod
    def planned(cls, *, skip_ct: bool, active_probes: bool) -> LadderState:
        """Return the units a default lookup attempts under these options."""
        units = [unit for family in FAMILIES for unit in family.units]
        if skip_ct:
            units.remove(progress.CT_UNIT)
        if not active_probes:
            units.remove("google_workspace")
        return cls(units)

    # ── Updates ──────────────────────────────────────────────────────────

    def apply(self, event: ProgressEvent) -> None:
        """Apply one progress event. Unknown units and repeats are ignored."""
        unit = event.unit
        if unit not in self._running or unit in self._settled:
            return
        if event.phase == "start":
            self._running[unit] = "running"
            return
        if event.result is not None:
            self._settle_result(unit, event.result)
        elif event.outcome is not None:
            self._settled[unit] = event.outcome

    def _settle_result(self, unit: str, result: SourceResult) -> None:
        if result.not_attempted:
            self._drop(unit)
            return
        self._settled[unit] = _result_outcome(result)

    def _drop(self, unit: str) -> None:
        self._order.remove(unit)
        del self._running[unit]
        self._settled.pop(unit, None)

    def finalize(self, results: Sequence[SourceResult]) -> None:
        """Settle every unit from the resolver's returned results.

        Results are authoritative over events. The resolver appends related
        inventory after the primary results, so only the first result per
        source name describes the queried domain.
        """
        primary: dict[str, SourceResult] = {}
        for result in results:
            primary.setdefault(result.source_name, result)
        for unit, result in primary.items():
            if unit in self._running:
                self._settle_result(unit, result)
        dns = primary.get(_DNS_UNIT)
        if dns is not None:
            if progress.CT_UNIT in self._running:
                self._settled[progress.CT_UNIT] = progress.ct_outcome_from_result(dns)
            if progress.MTA_STS_UNIT in self._running:
                self._settled[progress.MTA_STS_UNIT] = progress.mta_sts_outcome_from_result(dns)

    def abandon(self) -> None:
        """Mark units that never settled (an aggregate timeout) as unavailable."""
        if not self._settled:
            return
        for unit in self._order:
            self._settled.setdefault(unit, UnitOutcome("unavailable", "did not finish"))

    # ── Queries ──────────────────────────────────────────────────────────

    @property
    def units(self) -> tuple[str, ...]:
        return tuple(self._order)

    def outcome(self, unit: str) -> UnitOutcome | None:
        return self._settled.get(unit)

    @property
    def any_settled(self) -> bool:
        return bool(self._settled)

    @property
    def settled(self) -> bool:
        return all(unit in self._settled for unit in self._order)

    def families(self) -> list[tuple[Family, tuple[str, ...]]]:
        """Return each family with its planned units, skipping empty families."""
        rows: list[tuple[Family, tuple[str, ...]]] = []
        for family in FAMILIES:
            units = tuple(unit for unit in family.units if unit in self._running)
            if units:
                rows.append((family, units))
        return rows

    def family_outcome(self, units: Sequence[str]) -> UnitOutcome | None:
        """Combine unit outcomes into one row outcome, or None while running.

        A match anywhere in the family is a match. Otherwise an unavailable
        unit makes the row unavailable: a clean no-match must not hide it.
        """
        outcomes = [self._settled.get(unit) for unit in units]
        if any(outcome is None for outcome in outcomes):
            return None
        settled = [outcome for outcome in outcomes if outcome is not None]
        if any(outcome.state == "match" for outcome in settled):
            return UnitOutcome("match")
        unavailable = [outcome for outcome in settled if outcome.state == "unavailable"]
        if unavailable:
            return UnitOutcome("unavailable", "; ".join(o.reason for o in unavailable if o.reason) or None)
        return UnitOutcome("no_match")

    # ── Rendering ────────────────────────────────────────────────────────

    def health_line(self) -> str | None:
        """Return the one-line source-health summary, or None before any result.

        Only settled units are counted. Every planned unit settles in a real
        collection (``abandon`` settles the rest after a timeout), so a unit
        without an outcome means its result was never seen, not that it failed.

        ``6 sources: 3 matched, 2 no match, 1 unavailable (CT: crt.sh rate limited)``
        """
        settled = [(unit, self._settled[unit]) for unit in self._order if unit in self._settled]
        if not settled:
            return None
        counts = {"match": 0, "no_match": 0, "unavailable": 0}
        reasons: list[str] = []
        for unit, outcome in settled:
            counts[outcome.state] += 1
            if outcome.state == "unavailable":
                reasons.append(f"{UNIT_LABELS.get(unit, unit)}: {outcome.reason or 'unavailable'}")
        total = len(settled)
        parts = [
            f"{counts[state]} {word}"
            for state, word in (("match", "matched"), ("no_match", "no match"), ("unavailable", "unavailable"))
            if counts[state]
        ]
        line = f"{total} source{'s' if total != 1 else ''}: {', '.join(parts)}"
        if reasons:
            shown = reasons[:_MAX_LISTED_REASONS]
            extra = len(reasons) - len(shown)
            listed = "; ".join(shown) + (f"; {extra} more" if extra else "")
            line += f" ({listed})"
        return line

    def rows(self, frame: int) -> list[Text]:
        """Return one styled row per family for animation frame ``frame``."""
        frames = _ASCII_SPINNER_FRAMES if theme.ascii_active() else SPINNER_FRAMES
        rows: list[Text] = []
        for family, units in self.families():
            outcome = self.family_outcome(units)
            label = family.label.ljust(_LABEL_WIDTH)
            if outcome is None:
                mark = Text(frames[frame % len(frames)], style=theme.SUCCESS)
                word = Text("collecting", style=theme.MUTED)
            elif outcome.state == "match":
                mark = Text(theme.glyph("ok"), style=theme.SUCCESS)
                word = Text("matched")
            elif outcome.state == "no_match":
                mark = Text(theme.glyph("neutral"), style=theme.MUTED)
                word = Text("no match", style=theme.MUTED)
            else:
                mark = Text(theme.glyph("fail"), style=theme.ERROR)
                suffix = f" ({outcome.reason})" if outcome.reason else ""
                word = Text(f"unavailable{suffix}")
            rows.append(Text.assemble("  ", mark, " ", label, " ", word))
        return rows
