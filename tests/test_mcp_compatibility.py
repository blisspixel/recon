"""Contract tests for the narrow MCP SDK compatibility boundary."""

from __future__ import annotations

import shlex
import tomllib
from pathlib import Path

import pytest
import yaml

from recon_tool.mcp_client.doctor import DoctorCheck, _append_cache_metadata_check
from recon_tool.mcp_client.sdk_compat import SDK_FAMILY, mcp_application_options, model_wire_dict
from scripts import check_mcp_compatibility


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


def test_isolated_uv_operations_use_copy_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UV_LINK_MODE", "hardlink")

    env = check_mcp_compatibility._uv_environment()

    assert env["UV_LINK_MODE"] == "copy"
    assert check_mcp_compatibility.os.environ["UV_LINK_MODE"] == "hardlink"


def test_sdk_matrix_allows_its_companion_types_without_unlocking_other_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    exported = "# locked runtime\nmcp==2.0.0\nmcp-types==2.0.0\nhttpx==0.28.1\npydantic==2.12.5\n"

    def run(args: list[str], **_kwargs: object) -> check_mcp_compatibility.CommandResult:
        assert args == ["uv", "export", "--locked", "--no-dev", "--no-hashes", "--no-emit-project"]
        return check_mcp_compatibility.CommandResult(0, exported, "")

    monkeypatch.setattr(check_mcp_compatibility, "_run_command", run)
    constraints = tmp_path / "constraints.txt"
    result = check_mcp_compatibility._locked_constraints("uv", constraints)

    assert result.returncode == 0
    assert constraints.read_text(encoding="utf-8") == "# locked runtime\nhttpx==0.28.1\npydantic==2.12.5\n"


def test_local_ci_and_release_mcp_matrix_cover_rollback_floor_and_current_release() -> None:
    workflow_dir = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    workflow = workflow_dir / "ci.yml"
    jobs = yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"]
    matrix = jobs["mcp-compatibility"]["strategy"]["matrix"]["mcp-version"]
    assert tuple(matrix) == check_mcp_compatibility.DEFAULT_SDK_VERSIONS == ("1.28.1", "2.0.0", "2.2.0")
    release = yaml.safe_load((workflow_dir / "release.yml").read_text(encoding="utf-8"))
    commands = [step.get("run", "") for step in release["jobs"]["test"]["steps"]]
    (command,) = [command for command in commands if "scripts/check_mcp_compatibility.py" in command]
    arguments = shlex.split(command)
    for option in ("--sdk-version", "--require-compatible"):
        assert tuple(arguments[index + 1] for index, value in enumerate(arguments) if value == option) == tuple(matrix)
