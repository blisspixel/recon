"""Contract tests for the narrow MCP SDK compatibility boundary."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from recon_tool.mcp_client.doctor import DoctorCheck, _append_cache_metadata_check
from recon_tool.mcp_client.sdk_compat import SDK_FAMILY, mcp_application_options, model_wire_dict


class _Model:
    def model_dump(self, *, by_alias: bool, exclude_none: bool) -> dict[str, object]:
        assert by_alias is True
        assert exclude_none is True
        return {"structuredContent": {"result": []}}


class _InvalidModel:
    def model_dump(self, *, by_alias: bool, exclude_none: bool) -> list[object]:
        assert by_alias is True
        assert exclude_none is True
        return []


def test_model_wire_dict_preserves_protocol_aliases() -> None:
    assert model_wire_dict(_Model()) == {"structuredContent": {"result": []}}


def test_stable_sdk_needs_no_generation_specific_server_options() -> None:
    assert SDK_FAMILY == "v1"
    assert mcp_application_options() == {}


@pytest.mark.parametrize("model", [object(), _InvalidModel()])
def test_model_wire_dict_rejects_non_model_results(model: object) -> None:
    with pytest.raises(TypeError, match=r"MCP model|dictionary"):
        model_wire_dict(model)


def test_complete_result_metadata_accepts_conservative_private_cache() -> None:
    checks: list[DoctorCheck] = []

    _append_cache_metadata_check(
        checks,
        "server/discover metadata",
        {"ttlMs": 0, "cacheScope": "private", "resultType": "complete"},
    )

    assert checks == [
        DoctorCheck(
            "server/discover metadata",
            "ok",
            "ttlMs=0 cacheScope=private resultType=complete",
        )
    ]


@pytest.mark.parametrize(
    "wire",
    [
        {"ttlMs": True, "cacheScope": "private", "resultType": "complete"},
        {"ttlMs": -1, "cacheScope": "private", "resultType": "complete"},
        {"ttlMs": 0, "cacheScope": "shared", "resultType": "complete"},
        {"ttlMs": 0, "cacheScope": "private", "resultType": "partial"},
    ],
)
def test_complete_result_metadata_rejects_invalid_values(wire: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="invalid complete-result metadata"):
        _append_cache_metadata_check([], "metadata", wire)


def test_production_dependency_uses_characterized_stable_floor() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    dependencies = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["dependencies"]
    mcp_dependencies = [dependency for dependency in dependencies if dependency.startswith("mcp")]

    assert mcp_dependencies == ["mcp>=1.28.1,<2"]
