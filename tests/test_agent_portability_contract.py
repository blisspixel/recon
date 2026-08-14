"""Regressions for the frozen v2.15 agent-portability preregistration."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, cast

import pytest

from validation import agent_portability_contract as contract

ROOT = Path(__file__).resolve().parents[1]


def _payload() -> dict[str, Any]:
    return cast(dict[str, Any], contract.load_contract())


def _redigest(payload: dict[str, Any]) -> dict[str, Any]:
    payload["contract_digest_sha256"] = contract.canonical_digest(payload)
    return payload


def _write(tmp_path: Path, payload: dict[str, Any]) -> Path:
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _set_nested(payload: dict[str, Any], path: tuple[str | int, ...], value: object) -> None:
    target: object = payload
    for segment in path[:-1]:
        if isinstance(segment, str):
            target = cast(dict[str, object], target)[segment]
        else:
            target = cast(list[object], target)[segment]
    final = path[-1]
    if isinstance(final, str):
        cast(dict[str, object], target)[final] = value
    else:
        cast(list[object], target)[final] = value


def test_committed_contract_is_frozen_and_digest_verified() -> None:
    payload = _payload()

    digest = contract.validate_contract(payload)

    assert digest == "403a5860dc547ab0fd8961023d196e0b72ec6524ed2c1cb7da4253899628eafe"
    assert payload["selection"] == {
        "rule": (
            "Use every officially listed client that supports both Agent Skills and MCP stdio and "
            "for which recon ships a native scaffold at freeze time."
        ),
        "required_client_count": 3,
        "required_task_count": 5,
        "paired_comparison_count": 15,
        "total_session_count": 30,
    }


def test_canonical_digest_is_key_order_independent_and_omits_self_digest() -> None:
    payload = _payload()
    reversed_payload = dict(reversed(list(payload.items())))
    reversed_payload["contract_digest_sha256"] = "f" * 64

    assert contract.canonical_digest(reversed_payload) == contract.canonical_digest(payload)


def test_contract_tampering_fails_without_recomputed_digest() -> None:
    payload = _payload()
    payload["round_id"] = "changed"

    with pytest.raises(contract.ContractError, match="round_id has drifted"):
        contract.validate_contract(payload)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (
            ("standards", "agent_plugins", "source_revision"),
            "0" * 40,
            "source_revision has drifted",
        ),
        (
            ("standards", "agent_plugins", "schemas", 0, "sha256"),
            "0" * 64,
            "plugin schema digest has drifted",
        ),
        (
            ("selection", "total_session_count"),
            29,
            "total_session_count",
        ),
        (
            ("clients", 0, "native_scaffold"),
            "agents/cursor/mcp.json",
            "vscode native scaffold has drifted",
        ),
        (
            ("tasks", 0, "required_tool"),
            "assess_exposure",
            "required tool has drifted",
        ),
        (
            ("tasks", 0, "prompt"),
            "Summarize the public configuration observed for example.com.",
            "reserved .invalid domains",
        ),
        (
            ("variants", 1, "mcp_surface"),
            "core-profile",
            "complete 22-tool surface",
        ),
        (
            ("measures", "context_rule"),
            "Serialized bytes prove a representative model-context reduction.",
            "model-context evidence",
        ),
        (
            ("decisions", "portable_promotion", "maximum_task_success_regressions"),
            1,
            "maximum_task_success_regressions must remain zero",
        ),
        (
            ("decisions", "surface_profile", "minimum_instrumented_clients"),
            1,
            "at least two instrumented clients",
        ),
        (
            ("privacy", "transcripts_public"),
            True,
            "transcripts_public must remain false",
        ),
        (
            ("privacy", "local_output_root"),
            "validation/local",
            "local output root has drifted",
        ),
    ],
)
def test_semantic_relaxation_fails_even_after_redigest(
    path: tuple[str | int, ...],
    value: object,
    message: str,
) -> None:
    payload = copy.deepcopy(_payload())
    _set_nested(payload, path, value)
    _redigest(payload)

    with pytest.raises(contract.ContractError, match=message):
        contract.validate_contract(payload)


def test_client_order_drift_fails_even_after_redigest() -> None:
    payload = copy.deepcopy(_payload())
    clients = cast(list[object], payload["clients"])
    clients.reverse()
    _redigest(payload)

    with pytest.raises(contract.ContractError, match="client frame or order has drifted"):
        contract.validate_contract(payload)


def test_cli_reports_pass_without_network_or_identifiers(capsys: pytest.CaptureFixture[str]) -> None:
    assert contract.main([]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert "PASS: frozen v2.15 agent-portability contract" in captured.out
    assert "clients=3 tasks=5 sessions=30" in captured.out
    assert ".invalid" not in captured.out


def test_cli_fails_closed_for_invalid_contract(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _payload()
    payload["contract_digest_sha256"] = "0" * 64

    assert contract.main(["--contract", str(_write(tmp_path, payload))]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "FAIL: contract digest mismatch" in captured.err


def test_loader_rejects_oversized_input(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (contract.MAX_CONTRACT_BYTES + 1))

    with pytest.raises(contract.ContractError, match="contract size"):
        contract.load_contract(path)


def test_active_docs_publish_the_frozen_state_and_interchange_boundaries() -> None:
    declaration = (ROOT / "docs" / "agent-portability-evaluation-declaration.md").read_text(encoding="utf-8")
    active_docs = [
        (ROOT / "ROADMAP.md").read_text(encoding="utf-8"),
        (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8"),
        (ROOT / "docs" / "engineering-refinement-plan.md").read_text(encoding="utf-8"),
        (ROOT / "docs" / "strategic-gap-audit.md").read_text(encoding="utf-8"),
    ]

    assert "Status: frozen on 2026-08-14" in declaration
    assert "15 paired comparisons and 30 sessions" in declaration
    assert "Serialized MCP discovery bytes are not model-context evidence" in declaration
    assert "Open Knowledge Format v0.2 remains separately deferred" in declaration
    assert "Working Draft" in declaration
    assert all("agent-portability-evaluation-declaration.md" in document for document in active_docs)
    assert all("evaluation contract not yet frozen" not in document for document in active_docs)
