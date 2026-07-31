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


def test_server_options_match_the_active_sdk_generation() -> None:
    """The modern generation needs options the legacy one has no place for.

    v2 requires a caching hint on every cacheable method and reports the
    application version to clients; v1 has neither concept. Asserting per
    generation keeps this meaningful on the rollback pin as well.
    """
    options = mcp_application_options()
    if SDK_FAMILY == "v1":
        assert options == {}
        return
    assert set(options) == {"version", "cache_hints"}
    assert options["version"]
    assert set(options["cache_hints"]) == {
        "prompts/list",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "server/discover",
        "tools/list",
    }


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

    # Production runs the generation that speaks MCP 2026-07-28. 1.28.1 remains
    # the documented rollback pin and stays blocking in the compatibility
    # matrix, so both generations keep being exercised.
    assert mcp_dependencies == ["mcp>=2.0.0,<3"]
