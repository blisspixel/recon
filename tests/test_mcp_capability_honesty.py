"""Discovery must not advertise change notifications recon does not send."""

from __future__ import annotations

from recon_tool.mcp_client.doctor import advertised_change_notifications, capability_honesty_check


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
