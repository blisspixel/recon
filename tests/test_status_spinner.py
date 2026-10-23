# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportPrivateUsage=none
"""The lookup progress must stay truthful.

The source ladder replaced the single status spinner (issue #227). Its header
stays general, and a row settles only on a real progress event or a returned
result: waiting never simulates a phase change.
"""

from __future__ import annotations

import asyncio
import io

import pytest
from rich.console import Console

from recon_tool.cli.lookup import _CHAIN_STATUS_MESSAGE
from recon_tool.cli.source_ladder import HEADER, run_with_source_ladder
from recon_tool.formatter.source_ladder import LadderState
from recon_tool.models import SourceResult


def test_status_message_is_general_and_truthful() -> None:
    assert HEADER == "Collecting and correlating public evidence..."
    lower = HEADER.lower()
    for unobserved_phase in ("dns", "certificate", "identity", "posture", "passive"):
        assert unobserved_phase not in lower


def test_chain_status_describes_the_selected_operation() -> None:
    assert _CHAIN_STATUS_MESSAGE == "Following related-domain evidence..."


def _static_console() -> Console:
    return Console(file=io.StringIO(), force_terminal=False, width=100)


def test_returns_coroutine_result_unchanged() -> None:
    results = [SourceResult(source_name="oidc_discovery")]

    async def quick() -> tuple[str, list[SourceResult]]:
        return "info", results

    out = asyncio.run(run_with_source_ladder(_static_console(), quick(), skip_ct=False, active_probes=False))

    assert out == ("info", results)


def test_propagates_exceptions() -> None:
    async def boom() -> tuple[str, list[SourceResult]]:
        raise ValueError("lookup failed")

    with pytest.raises(ValueError, match="lookup failed"):
        asyncio.run(run_with_source_ladder(_static_console(), boom(), skip_ct=False, active_probes=False))


def test_waiting_does_not_settle_any_row() -> None:
    state = LadderState.planned(skip_ct=False, active_probes=False)
    assert not state.any_settled
    assert all("collecting" in row.plain for row in state.rows(0))
    assert state.health_line() is None
