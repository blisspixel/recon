"""The source ladder and its source-health line (issue #227).

The ladder is rendered here against synthetic progress events, never a live
collection. Frame pacing uses a fake clock, so the 12 fps cap and the
idle-after-settle rule are checked without wall-clock timing.
"""

from __future__ import annotations

import asyncio
import io
import re
from collections.abc import Iterator

import pytest
from rich.console import Console

from recon_tool.cli import source_ladder as live_mod
from recon_tool.cli.source_ladder import (
    MAX_FPS,
    SYNC_BEGIN,
    SYNC_END,
    LiveLadder,
    animation_disabled_reason,
    run_with_source_ladder,
)
from recon_tool.collection_progress import ProgressEvent, UnitOutcome
from recon_tool.formatter import theme
from recon_tool.formatter.source_ladder import FAMILIES, LadderState, short_reason
from recon_tool.models import EvidenceRecord, SourceResult

_ESC = "\x1b"
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _plain(text: str) -> str:
    return _ANSI.sub("", text)


def _done(unit: str, **fields: object) -> ProgressEvent:
    return ProgressEvent(unit=unit, phase="done", result=SourceResult(source_name=unit, **fields))  # type: ignore[arg-type]


def _matched(unit: str) -> ProgressEvent:
    return _done(unit, tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", m365_detected=True)


@pytest.fixture
def unicode_glyphs() -> Iterator[None]:
    previous = theme.ascii_active()
    theme.set_ascii_active(False)
    try:
        yield
    finally:
        theme.set_ascii_active(previous)


# ── Model and wording ──────────────────────────────────────────────────────


def test_families_cover_the_default_pool_and_dns_internal_units() -> None:
    units = {unit for family in FAMILIES for unit in family.units}
    assert units == {
        "dns_records",
        "oidc_discovery",
        "user_realm",
        "google_identity",
        "google_workspace",
        "mta_sts",
        "ct",
    }
    assert len(FAMILIES) == 6


def test_plan_follows_options() -> None:
    assert "ct" not in LadderState.planned(skip_ct=True, active_probes=False).units
    assert "google_workspace" not in LadderState.planned(skip_ct=False, active_probes=False).units
    assert "google_workspace" in LadderState.planned(skip_ct=False, active_probes=True).units


def test_health_line_counts_each_state() -> None:
    state = LadderState.planned(skip_ct=False, active_probes=False)
    for event in (
        _matched("oidc_discovery"),
        _matched("dns_records"),
        _done("user_realm", error="Could not resolve display name or default domain"),
        _done("google_identity", error="Network error: timed out", source_unavailable=True),
        ProgressEvent("mta_sts", "done", outcome=UnitOutcome("no_match")),
        ProgressEvent("ct", "done", outcome=UnitOutcome("unavailable", "crt.sh, certspotter rate limited")),
    ):
        state.apply(event)
    assert state.settled
    assert state.health_line() == (
        "6 sources: 2 matched, 2 no match, 2 unavailable "
        "(Google identity: timeout; CT: crt.sh, certspotter rate limited)"
    )


def test_health_line_omits_zero_counts_and_uses_singular() -> None:
    state = LadderState(["oidc_discovery"])
    state.apply(_matched("oidc_discovery"))
    assert state.health_line() == "1 source: 1 matched"


def test_health_line_bounds_the_reason_list() -> None:
    state = LadderState.planned(skip_ct=False, active_probes=True)
    for unit in state.units:
        state.apply(ProgressEvent(unit, "done", outcome=UnitOutcome("unavailable", "timeout")))
    line = state.health_line()
    assert line is not None
    assert line.startswith("7 sources: 7 unavailable (")
    assert line.endswith("; 4 more)")


def test_nothing_settled_means_no_line() -> None:
    state = LadderState.planned(skip_ct=False, active_probes=False)
    state.apply(ProgressEvent("dns_records", "start"))
    assert state.health_line() is None


def test_not_attempted_probe_leaves_the_count() -> None:
    state = LadderState.planned(skip_ct=False, active_probes=True)
    state.apply(_done("google_workspace", not_attempted=True))
    assert "google_workspace" not in state.units


def test_repeated_and_unknown_events_are_ignored() -> None:
    state = LadderState(["oidc_discovery"])
    state.apply(_matched("oidc_discovery"))
    state.apply(_done("oidc_discovery", error="boom", source_unavailable=True))
    state.apply(_matched("related_source"))
    assert state.outcome("oidc_discovery") == UnitOutcome("match")


def test_finalize_uses_primary_results_and_derives_dns_units() -> None:
    state = LadderState.planned(skip_ct=False, active_probes=False)
    dns = SourceResult(
        source_name="dns_records",
        detected_services=("DMARC",),
        evidence=(EvidenceRecord("MTA_STS", "v=STSv1; id=1", "MTA-STS", "mta-sts"),),
        ct_subdomain_count=4,
        ct_provider_used="crt.sh",
    )
    related = SourceResult(source_name="dns_records", error="related failure", source_unavailable=True)
    state.finalize(
        [
            _matched("oidc_discovery").result,  # type: ignore[list-item]
            SourceResult(source_name="user_realm", error="Could not resolve display name or default domain"),
            SourceResult(source_name="google_identity", error="No federated IdP redirect observed"),
            SourceResult(source_name="google_workspace", not_attempted=True),
            dns,
            related,
        ]
    )
    assert state.outcome("dns_records") == UnitOutcome("match")
    assert state.outcome("ct") == UnitOutcome("match")
    assert state.outcome("mta_sts") == UnitOutcome("match")
    assert state.health_line() == "6 sources: 4 matched, 2 no match"


def test_dns_with_lost_channels_and_no_match_is_unavailable() -> None:
    state = LadderState(["dns_records"])
    state.apply(_done("dns_records", degraded_sources=("dns:mx", "dns:ns")))
    outcome = state.outcome("dns_records")
    assert outcome is not None
    assert outcome.state == "unavailable"
    assert outcome.reason == "2 of 14 record types unavailable"


def test_whole_dns_failure_marks_derived_units_unavailable() -> None:
    state = LadderState.planned(skip_ct=False, active_probes=False)
    state.finalize([SourceResult(source_name="dns_records", error="DNS error", source_unavailable=True)])
    assert state.outcome("ct") == UnitOutcome("unavailable", "DNS unavailable")
    assert state.outcome("mta_sts") == UnitOutcome("unavailable", "DNS unavailable")


def test_abandon_marks_unfinished_units_after_partial_progress() -> None:
    state = LadderState(["oidc_discovery", "dns_records"])
    state.apply(_matched("oidc_discovery"))
    state.abandon()
    assert state.health_line() == "2 sources: 1 matched, 1 unavailable (DNS: did not finish)"


def test_abandon_without_progress_reports_nothing() -> None:
    state = LadderState(["oidc_discovery"])
    state.abandon()
    assert state.health_line() is None


def test_family_outcome_precedence() -> None:
    state = LadderState(["google_identity", "google_workspace"])
    state.apply(_done("google_identity", error="No federated IdP redirect observed"))
    state.apply(_done("google_workspace", error="Network error: timed out", source_unavailable=True))
    assert state.family_outcome(("google_identity", "google_workspace")) == UnitOutcome("unavailable", "timeout")
    state = LadderState(["google_identity", "google_workspace"])
    state.apply(_done("google_identity", detected_services=("Google Workspace",)))
    state.apply(_done("google_workspace", error="timed out", source_unavailable=True))
    assert state.family_outcome(("google_identity", "google_workspace")) == UnitOutcome("match")


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (None, "unavailable"),
        (
            "Network error: could not resolve login.example.com, so the destination could not be validated",
            "could not resolve",
        ),
        (
            "SSRF blocked, mta-sts.example.com skipped: resolves to a private address (10.0.0.5)",
            "private address skipped",
        ),
        ("DNS resolution unavailable for example.com: none of 40 DNS queries", "no resolver response"),
        ("Read timed out", "timeout"),
        ("HTTP 429 from provider", "rate limited"),
        ("HTTP 503 from OIDC discovery endpoint", "HTTP 503"),
        ("\x1b]8;;evil\x07 injected text", "error"),
    ],
)
def test_short_reason_uses_a_fixed_vocabulary(error: str | None, reason: str) -> None:
    assert short_reason(error) == reason


# ── Rendering ──────────────────────────────────────────────────────────────


def test_rows_render_against_fake_events(unicode_glyphs: None) -> None:
    state = LadderState.planned(skip_ct=False, active_probes=False)
    for unit in state.units:
        state.apply(ProgressEvent(unit, "start"))
    state.apply(_matched("oidc_discovery"))
    state.apply(_done("user_realm", error="Could not resolve display name or default domain"))
    state.apply(ProgressEvent("ct", "done", outcome=UnitOutcome("unavailable", "crt.sh rate limited")))

    console = Console(record=True, force_terminal=True, width=100, color_system="standard")
    for row in state.rows(frame=0):
        console.print(row)
    text = console.export_text(styles=False, clear=False)

    assert "\u2713 Microsoft tenant discovery" in text
    assert "matched" in text
    assert "\u2013 Microsoft user realm" in text  # the neutral (dash) source mark
    assert "\u2717 Certificate transparency" in text
    assert "unavailable (crt.sh rate limited)" in text
    assert text.count("⠋") == 3  # DNS, Google identity, MTA-STS still running
    styled = console.export_text(styles=True)
    assert "\x1b[32m\u2713" in styled  # success role on the marker
    assert "\x1b[31m\u2717" in styled  # error role on the marker


def test_rows_use_ascii_forms_in_ascii_mode() -> None:
    previous = theme.ascii_active()
    theme.set_ascii_active(True)
    try:
        state = LadderState(["oidc_discovery", "user_realm", "dns_records", "google_identity"])
        state.apply(_matched("oidc_discovery"))
        state.apply(_done("user_realm"))
        state.apply(_done("dns_records", error="x", source_unavailable=True))
        rows = [row.plain for row in state.rows(frame=1)]
    finally:
        theme.set_ascii_active(previous)
    assert rows[0].lstrip().startswith("x DNS records")
    assert rows[1].lstrip().startswith("ok Microsoft tenant discovery")
    assert rows[2].lstrip().startswith("- Microsoft user realm")
    assert rows[3].lstrip().startswith("/ Google identity")
    assert all(row.isascii() for row in rows)


# ── Motion ─────────────────────────────────────────────────────────────────


class _FakeClock:
    """Monotonic clock advanced only by the fake sleep."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
        await asyncio.sleep(0)


def _terminal_console() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    return Console(file=buffer, force_terminal=True, width=80, color_system="standard"), buffer


def test_frame_rate_is_capped_at_twelve_per_second() -> None:
    clock = _FakeClock()
    console, _buffer = _terminal_console()
    state = LadderState.planned(skip_ct=False, active_probes=False)

    async def scenario() -> LiveLadder:
        # A caller asking for a faster interval is still held to the cap.
        live = LiveLadder(state, console, interval=0.001, clock=clock, sleep=clock.sleep)
        live.start()
        while clock.now < 2.0:
            await asyncio.sleep(0)
        await live.stop()
        return live

    live = asyncio.run(scenario())
    assert all(seconds >= 1 / MAX_FPS for seconds in clock.sleeps)
    elapsed = live.frame_times[-1] - live.frame_times[0]
    assert live.frames <= elapsed * MAX_FPS + 1 + 1e-6
    gaps = [b - a for a, b in zip(live.frame_times, live.frame_times[1:], strict=False)]
    assert gaps
    assert min(gaps) >= 1 / MAX_FPS - 1e-9


def test_live_region_stops_after_settle() -> None:
    clock = _FakeClock()
    console, buffer = _terminal_console()
    state = LadderState(["oidc_discovery"])

    async def scenario() -> tuple[LiveLadder, set[asyncio.Task[object]]]:
        live = LiveLadder(state, console, clock=clock, sleep=clock.sleep)
        live.start()
        await asyncio.sleep(0)
        state.apply(_matched("oidc_discovery"))
        await live.stop()
        current = asyncio.current_task()
        others = {task for task in asyncio.all_tasks() if task is not current}
        return live, others  # type: ignore[return-value]

    live, others = asyncio.run(scenario())
    assert live.task is not None
    assert live.task.done()
    assert others == set()
    frames_after_stop = live.frames
    assert frames_after_stop >= 1
    output = buffer.getvalue()
    assert output.startswith("\x1b[?25l")  # cursor hidden while live
    assert output.endswith(SYNC_END + "\x1b[?25h")  # region cleared, cursor restored
    assert output.count(SYNC_BEGIN) == output.count(SYNC_END)


def test_events_never_draw() -> None:
    clock = _FakeClock()
    console, _buffer = _terminal_console()
    state = LadderState.planned(skip_ct=False, active_probes=False)

    async def scenario() -> LiveLadder:
        live = LiveLadder(state, console, clock=clock, sleep=clock.sleep)
        live.start()
        await asyncio.sleep(0)
        drawn = live.frames
        for unit in state.units:
            state.apply(ProgressEvent(unit, "start"))
        assert live.frames == drawn
        await live.stop()
        return live

    asyncio.run(scenario())


def test_every_frame_is_synchronized(monkeypatch: pytest.MonkeyPatch) -> None:
    console, buffer = _terminal_console()

    def allow_animation(_console: Console) -> None:
        return None

    monkeypatch.setattr(live_mod, "_console_disabled_reason", allow_animation)

    async def collect() -> tuple[str, list[SourceResult]]:
        await asyncio.sleep(0.2)
        return "info", [SourceResult(source_name="oidc_discovery", tenant_id="t", m365_detected=True)]

    asyncio.run(run_with_source_ladder(console, collect(), skip_ct=True, active_probes=False))
    output = buffer.getvalue()
    frames = output.split(SYNC_BEGIN)[1:]
    assert frames, output
    assert all(SYNC_END in frame for frame in frames)
    assert "Collecting and correlating public evidence..." in output
    # The rows collapse: stderr ends with the health line alone.
    assert output.endswith("\x1b[?25h1 source: 1 matched\n")


# ── Disable conditions ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("environ", "kwargs", "reason"),
    [
        ({}, {"color_flag": False}, "--no-color"),
        ({"NO_COLOR": "1"}, {}, "NO_COLOR"),
        ({"TERM": "dumb"}, {}, "TERM=dumb"),
        ({"CI": "true"}, {}, "CI"),
        ({"RECON_NO_ANIMATION": "1"}, {}, "RECON_NO_ANIMATION"),
        ({}, {"stderr_tty": False}, "stderr is not a terminal"),
        ({}, {"debug": True}, "--debug"),
        ({}, {"legacy_windows": True}, "legacy Windows console"),
    ],
)
def test_each_disable_condition(environ: dict[str, str], kwargs: dict[str, object], reason: str) -> None:
    arguments: dict[str, object] = {"stderr_tty": True, "color_flag": None, **kwargs}
    assert animation_disabled_reason(environ, **arguments) == reason  # type: ignore[arg-type]


@pytest.mark.parametrize("environ", [{}, {"CI": "0"}, {"CI": "false"}, {"RECON_NO_ANIMATION": "0"}, {"NO_COLOR": ""}])
def test_animation_allowed_on_an_interactive_terminal(environ: dict[str, str]) -> None:
    assert animation_disabled_reason(environ, stderr_tty=True, color_flag=None) is None


@pytest.mark.parametrize(
    "env",
    [
        {"NO_COLOR": "1"},
        {"CI": "true"},
        {"TERM": "dumb"},
        {"RECON_NO_ANIMATION": "1"},
        {},  # pytest's stderr is not a terminal
    ],
)
def test_disabled_ladder_prints_only_the_static_line(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> None:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    console, buffer = _terminal_console()

    async def collect() -> tuple[str, list[SourceResult]]:
        return "info", [
            SourceResult(source_name="oidc_discovery", tenant_id="t", m365_detected=True),
            SourceResult(source_name="user_realm", error="Network error", source_unavailable=True),
        ]

    asyncio.run(run_with_source_ladder(console, collect(), skip_ct=True, active_probes=False))
    output = buffer.getvalue()
    assert _ESC not in output
    assert output == "2 sources: 1 matched, 1 unavailable (user realm: error)\n"


def test_failed_collection_still_reports_settled_units() -> None:
    console, buffer = _terminal_console()

    async def collect() -> tuple[str, list[SourceResult]]:
        from recon_tool import collection_progress

        collection_progress.emit("oidc_discovery", "done", result=SourceResult(source_name="oidc_discovery"))
        raise TimeoutError("aggregate timeout")

    with pytest.raises(TimeoutError):
        asyncio.run(run_with_source_ladder(console, collect(), skip_ct=True, active_probes=False))
    line = _plain(buffer.getvalue())
    assert line.startswith("5 sources: 1 no match, 4 unavailable (DNS: did not finish;")
