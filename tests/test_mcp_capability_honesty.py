"""Discovery must not advertise change notifications recon does not send."""

from __future__ import annotations

import pytest

from recon_tool.mcp_client.doctor import (
    advertised_change_notifications,
    capability_honesty_check,
    runtime_capability_honesty_check,
)
from recon_tool.mcp_client.sdk_compat import (
    change_notification_opt_out_required,
    change_notifications_must_be_absent,
)


def _section(**flags: bool) -> dict[str, object]:
    section: dict[str, object] = {}
    for name, value in flags.items():
        section[name] = value
    return section


def test_absent_and_false_flags_are_honest() -> None:
    honest: dict[str, object] = {
        "prompts": _section(listChanged=False),
        "resources": _section(subscribe=False, listChanged=False),
        "tools": _section(),
    }
    assert advertised_change_notifications(honest) == ()
    assert advertised_change_notifications({}) == ()
    assert capability_honesty_check({"capabilities": honest}).status == "ok"
    omitted = capability_honesty_check({})
    assert omitted.status == "fail"
    assert omitted.detail == "server/discover omitted capabilities"


def test_true_flags_fail_the_doctor_check() -> None:
    claimed: dict[str, object] = {
        "tools": _section(listChanged=True),
        "resources": _section(subscribe=True),
    }
    assert advertised_change_notifications(claimed) == ("resources.subscribe", "tools.listChanged")
    failed = capability_honesty_check({"capabilities": claimed})
    assert failed.status == "fail"
    assert failed.detail == (
        "advertised change notifications recon does not send: resources.subscribe, tools.listChanged"
    )
    assert failed.next is not None


def test_older_v2_warns_when_the_sdk_cannot_hide_the_flags() -> None:
    claimed: dict[str, object] = {"tools": _section(listChanged=True)}
    warned = runtime_capability_honesty_check({"capabilities": claimed}, opt_out_required=False)
    assert warned.status == "warn"
    assert "mcp 2.3.0" in warned.detail
    assert "listChanged" not in warned.detail
    still_fails = runtime_capability_honesty_check({"capabilities": claimed}, opt_out_required=True)
    assert still_fails.status == "fail"
    omitted = runtime_capability_honesty_check({}, opt_out_required=False)
    assert omitted.status == "fail"
    assert omitted.detail == "server/discover omitted capabilities"
    honest = runtime_capability_honesty_check(
        {"capabilities": {"tools": _section(listChanged=False)}},
        opt_out_required=False,
    )
    assert honest.status == "ok"


@pytest.mark.parametrize(
    ("family", "raw", "required"),
    [
        ("v1", "1.28.1", False),
        ("v2", "2.0.0", False),
        ("v2", "2.2.9", False),
        ("v2", "2.3.0", True),
        ("v2", "2.3.1", True),
        ("v2", "2.10.0", True),
        ("v2", "2.3.0rc1", True),
    ],
)
def test_opt_out_requirement_starts_at_mcp_2_3(family: str, raw: str, required: bool) -> None:
    assert change_notification_opt_out_required(family, raw) is required


def test_installed_sdk_matches_the_locked_opt_out_rule() -> None:
    assert change_notifications_must_be_absent() is True
