"""Validate the frozen v2.15 agent-portability evaluation contract.

This module is intentionally network-free. It validates the public
preregistration, pins the selected standards snapshot, checks the exact client
and task frame, and verifies a canonical SHA-256 digest before any evaluation
session may run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "docs" / "agent-portability-evaluation-contract.json"
MAX_CONTRACT_BYTES = 1 << 20

_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ROOT_FIELDS = {
    "schema_version",
    "status",
    "private",
    "round_id",
    "frozen_at",
    "standards",
    "selection",
    "clients",
    "tasks",
    "variants",
    "failure_cases",
    "measures",
    "decisions",
    "privacy",
    "contract_digest_sha256",
}
_CLIENT_IDS = ("vscode", "cursor", "kiro")
_CLIENT_SCAFFOLDS = {
    "vscode": "agents/vscode/mcp.json",
    "cursor": "agents/cursor/mcp.json",
    "kiro": "agents/kiro/mcp.json",
}
_TASK_IDS = (
    "single-domain-summary",
    "explanation-provenance",
    "posture-gaps",
    "posture-comparison",
    "bounded-catalog-absence",
)
_TASK_TOOLS = {
    "single-domain-summary": "lookup_tenant",
    "explanation-provenance": "lookup_tenant",
    "posture-gaps": "find_hardening_gaps",
    "posture-comparison": "compare_postures",
    "bounded-catalog-absence": "get_fingerprints",
}
_VARIANT_IDS = ("native-control", "portable-full")
_FAILURE_IDS = (
    "unsupported-spec-version",
    "invalid-skill",
    "invalid-server-entry",
    "mcp-handshake-failure",
    "update-state-preservation",
)
_PLUGIN_SCHEMA_SHA256 = "0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883"
_MCP_SCHEMA_SHA256 = "6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb"
_AGENT_PLUGINS_REVISION = "bd383552095128f6effe895b9257cfd580a6d179"
_AGENT_SKILLS_REVISION = "69ef37e9424c0a7ea9dd2293b559e43ec8176379"


class ContractError(ValueError):
    """Raised when the public preregistration is invalid or has drifted."""


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ContractError(f"{label} must be an object with string keys")
    return value


def _sequence(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{label} must be a non-empty string")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{label} must be an integer")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{label} must be a boolean")
    return value


def _exact_fields(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ContractError(f"{label} fields differ (missing={missing}, extra={extra})")


def _string_list(value: object, label: str, *, nonempty: bool = True) -> list[str]:
    items = _sequence(value, label)
    if nonempty and not items:
        raise ContractError(f"{label} must not be empty")
    if not all(isinstance(item, str) and item.strip() for item in items):
        raise ContractError(f"{label} must contain only non-empty strings")
    return items  # type: ignore[return-value]


def canonical_digest(payload: dict[str, object]) -> str:
    """Return the canonical digest with the self-digest field omitted."""

    canonical = dict(payload)
    canonical.pop("contract_digest_sha256", None)
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_plugin_snapshot(plugins: dict[str, object]) -> None:
    _exact_fields(
        plugins,
        {
            "version",
            "status",
            "specification_url",
            "compatible_clients_url",
            "source_revision",
            "schemas",
        },
        "standards.agent_plugins",
    )
    expected_plugin_values = {
        "version": "1.0.0",
        "status": "Working Draft",
        "specification_url": "https://agent-plugins.org/specification",
        "compatible_clients_url": "https://agent-plugins.org/compatible-clients",
        "source_revision": _AGENT_PLUGINS_REVISION,
    }
    for field, expected in expected_plugin_values.items():
        if _text(plugins[field], f"standards.agent_plugins.{field}") != expected:
            raise ContractError(f"standards.agent_plugins.{field} has drifted")

    schemas = _sequence(plugins["schemas"], "standards.agent_plugins.schemas")
    if len(schemas) != 2:
        raise ContractError("Agent Plugins must pin exactly the plugin and MCP schemas")
    expected_schemas = {
        "plugin": (
            "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            1805,
            _PLUGIN_SCHEMA_SHA256,
        ),
        "mcp": (
            "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
            3408,
            _MCP_SCHEMA_SHA256,
        ),
    }
    observed_kinds: set[str] = set()
    for index, raw_schema in enumerate(schemas):
        schema = _mapping(raw_schema, f"standards.agent_plugins.schemas[{index}]")
        _exact_fields(schema, {"kind", "url", "bytes", "sha256"}, f"schema[{index}]")
        kind = _text(schema["kind"], f"schema[{index}].kind")
        if kind not in expected_schemas or kind in observed_kinds:
            raise ContractError(f"unexpected or duplicate Agent Plugins schema kind: {kind}")
        observed_kinds.add(kind)
        expected_url, expected_bytes, expected_sha = expected_schemas[kind]
        if _text(schema["url"], f"schema[{index}].url") != expected_url:
            raise ContractError(f"{kind} schema URL has drifted")
        if _integer(schema["bytes"], f"schema[{index}].bytes") != expected_bytes:
            raise ContractError(f"{kind} schema byte count has drifted")
        digest = _text(schema["sha256"], f"schema[{index}].sha256")
        if not _HEX_SHA256.fullmatch(digest) or digest != expected_sha:
            raise ContractError(f"{kind} schema digest has drifted")


def _validate_skills_snapshot(skills: dict[str, object]) -> None:
    _exact_fields(
        skills,
        {
            "specification_url",
            "source_revision",
            "allowed_frontmatter_fields",
            "allowed_tools_status",
        },
        "standards.agent_skills",
    )
    if _text(skills["specification_url"], "agent_skills.specification_url") != ("https://agentskills.io/specification"):
        raise ContractError("Agent Skills specification URL has drifted")
    if _text(skills["source_revision"], "agent_skills.source_revision") != _AGENT_SKILLS_REVISION:
        raise ContractError("Agent Skills source revision has drifted")
    allowed_fields = _string_list(skills["allowed_frontmatter_fields"], "allowed_frontmatter_fields")
    if allowed_fields != [
        "name",
        "description",
        "license",
        "compatibility",
        "metadata",
        "allowed-tools",
    ]:
        raise ContractError("Agent Skills frontmatter field set has drifted")
    if _text(skills["allowed_tools_status"], "allowed_tools_status") != "experimental":
        raise ContractError("allowed-tools must remain explicitly experimental")


def _validate_standard_snapshot(standards: dict[str, object]) -> None:
    _exact_fields(standards, {"checked_at", "agent_plugins", "agent_skills"}, "standards")
    if _text(standards["checked_at"], "standards.checked_at") != "2026-08-14":
        raise ContractError("standards.checked_at must remain the frozen review date")
    _validate_plugin_snapshot(_mapping(standards["agent_plugins"], "standards.agent_plugins"))
    _validate_skills_snapshot(_mapping(standards["agent_skills"], "standards.agent_skills"))


def _validate_selection(payload: dict[str, object]) -> None:
    selection = _mapping(payload["selection"], "selection")
    _exact_fields(
        selection,
        {
            "rule",
            "required_client_count",
            "required_task_count",
            "paired_comparison_count",
            "total_session_count",
        },
        "selection",
    )
    _text(selection["rule"], "selection.rule")
    if _integer(selection["required_client_count"], "required_client_count") != len(_CLIENT_IDS):
        raise ContractError("required_client_count does not match the frozen client frame")
    if _integer(selection["required_task_count"], "required_task_count") != len(_TASK_IDS):
        raise ContractError("required_task_count does not match the frozen task frame")
    paired = len(_CLIENT_IDS) * len(_TASK_IDS)
    if _integer(selection["paired_comparison_count"], "paired_comparison_count") != paired:
        raise ContractError("paired_comparison_count does not match clients times tasks")
    if _integer(selection["total_session_count"], "total_session_count") != paired * len(_VARIANT_IDS):
        raise ContractError("total_session_count does not match the paired matrix")


def _validate_clients(payload: dict[str, object]) -> None:
    clients = _sequence(payload["clients"], "clients")
    observed: list[str] = []
    for index, raw_client in enumerate(clients):
        client = _mapping(raw_client, f"clients[{index}]")
        _exact_fields(
            client,
            {
                "id",
                "name",
                "official_components",
                "mcp_transports",
                "native_scaffold",
                "version_policy",
                "required",
            },
            f"clients[{index}]",
        )
        client_id = _text(client["id"], f"clients[{index}].id")
        observed.append(client_id)
        _text(client["name"], f"clients[{index}].name")
        if _string_list(client["official_components"], "official_components") != [
            "agent-skills",
            "mcp",
        ]:
            raise ContractError(f"{client_id} must support Agent Skills and MCP")
        transports = _string_list(client["mcp_transports"], "mcp_transports")
        if "stdio" not in transports:
            raise ContractError(f"{client_id} must support MCP stdio")
        declared_scaffold = _text(client["native_scaffold"], f"clients[{index}].native_scaffold")
        if declared_scaffold != _CLIENT_SCAFFOLDS.get(client_id):
            raise ContractError(f"{client_id} native scaffold has drifted")
        scaffold = ROOT / declared_scaffold
        if not scaffold.is_file():
            raise ContractError(f"{client_id} native scaffold does not exist")
        if _text(client["version_policy"], "version_policy") != "record-exact-version-at-run":
            raise ContractError(f"{client_id} version policy has drifted")
        if _boolean(client["required"], "required") is not True:
            raise ContractError(f"{client_id} must remain required")
    if tuple(observed) != _CLIENT_IDS:
        raise ContractError(f"client frame or order has drifted: {observed}")


def _validate_tasks(payload: dict[str, object]) -> None:
    tasks = _sequence(payload["tasks"], "tasks")
    observed: list[str] = []
    for index, raw_task in enumerate(tasks):
        task = _mapping(raw_task, f"tasks[{index}]")
        _exact_fields(
            task,
            {"id", "prompt", "surface", "required_tool", "success_criteria"},
            f"tasks[{index}]",
        )
        task_id = _text(task["id"], f"tasks[{index}].id")
        observed.append(task_id)
        prompt = _text(task["prompt"], f"tasks[{index}].prompt")
        _text(task["surface"], f"tasks[{index}].surface")
        required_tool = _text(task["required_tool"], f"tasks[{index}].required_tool")
        if required_tool != _TASK_TOOLS.get(task_id):
            raise ContractError(f"{task_id} required tool has drifted")
        criteria = _string_list(task["success_criteria"], f"tasks[{index}].success_criteria")
        if len(criteria) < 2:
            raise ContractError(f"{task_id} needs at least two frozen success criteria")
        if task_id != "bounded-catalog-absence" and ".invalid" not in prompt:
            raise ContractError(f"{task_id} must use only reserved .invalid domains")
        if "http://" in prompt or "https://" in prompt:
            raise ContractError(f"{task_id} prompt must not contain a target URL")
    if tuple(observed) != _TASK_IDS:
        raise ContractError(f"task frame or order has drifted: {observed}")


def _validate_variants_and_failures(payload: dict[str, object]) -> None:
    variants = _sequence(payload["variants"], "variants")
    observed_variants: list[str] = []
    for index, raw_variant in enumerate(variants):
        variant = _mapping(raw_variant, f"variants[{index}]")
        _exact_fields(
            variant,
            {"id", "packaging", "mcp_surface", "skills", "stable_surface_mutation"},
            f"variants[{index}]",
        )
        observed_variants.append(_text(variant["id"], f"variants[{index}].id"))
        _text(variant["packaging"], "packaging")
        if _text(variant["mcp_surface"], "mcp_surface") != "complete-22-tool":
            raise ContractError("both paired variants must retain the complete 22-tool surface")
        _text(variant["skills"], "skills")
        if _boolean(variant["stable_surface_mutation"], "stable_surface_mutation"):
            raise ContractError("the preregistered variants must not mutate stable surfaces")
    if tuple(observed_variants) != _VARIANT_IDS:
        raise ContractError(f"variant frame or order has drifted: {observed_variants}")

    failures = _sequence(payload["failure_cases"], "failure_cases")
    observed_failures: list[str] = []
    for index, raw_failure in enumerate(failures):
        failure = _mapping(raw_failure, f"failure_cases[{index}]")
        _exact_fields(failure, {"id", "expected_behavior"}, f"failure_cases[{index}]")
        observed_failures.append(_text(failure["id"], f"failure_cases[{index}].id"))
        _text(failure["expected_behavior"], f"failure_cases[{index}].expected_behavior")
    if tuple(observed_failures) != _FAILURE_IDS:
        raise ContractError(f"failure frame or order has drifted: {observed_failures}")


def _validate_measures(payload: dict[str, object]) -> None:
    measures = _mapping(payload["measures"], "measures")
    _exact_fields(measures, {"blocking", "diagnostic", "context_rule"}, "measures")
    blocking = _string_list(measures["blocking"], "measures.blocking")
    for required in ("task_success", "unsupported_claim_count", "correct_tool_selection"):
        if required not in blocking:
            raise ContractError(f"blocking measure {required} is missing")
    diagnostic = _string_list(measures["diagnostic"], "measures.diagnostic")
    for required in (
        "round_trips",
        "discovery_bytes",
        "result_bytes",
        "client_visible_model_context_bytes_when_instrumented",
        "failure_recovery_quality",
    ):
        if required not in diagnostic:
            raise ContractError(f"diagnostic measure {required} is missing")
    context_rule = _text(measures["context_rule"], "measures.context_rule")
    if "not model-context evidence" not in context_rule:
        raise ContractError("context_rule must reject serialized bytes as model-context evidence")


def _validate_portable_decision(decisions: dict[str, object]) -> None:
    portable = _mapping(decisions["portable_promotion"], "portable_promotion")
    _exact_fields(
        portable,
        {
            "required_schema_pass",
            "required_client_passes",
            "maximum_task_success_regressions",
            "maximum_portable_only_unsupported_claims",
            "maximum_round_trip_increase_per_task",
            "claim_wording",
        },
        "portable_promotion",
    )
    if not _boolean(portable["required_schema_pass"], "required_schema_pass"):
        raise ContractError("portable schema validation must remain blocking")
    if _integer(portable["required_client_passes"], "required_client_passes") != len(_CLIENT_IDS):
        raise ContractError("portable promotion must require every frozen client")
    for zero_field in (
        "maximum_task_success_regressions",
        "maximum_portable_only_unsupported_claims",
    ):
        if _integer(portable[zero_field], zero_field) != 0:
            raise ContractError(f"{zero_field} must remain zero")
    if _integer(portable["maximum_round_trip_increase_per_task"], "round_trip_increase") != 1:
        raise ContractError("round-trip increase budget must remain one")
    if "pinned" not in _text(portable["claim_wording"], "claim_wording").lower():
        raise ContractError("portable claim wording must identify the pinned snapshot")


def _validate_surface_decision(decisions: dict[str, object]) -> None:
    surface = _mapping(decisions["surface_profile"], "surface_profile")
    _exact_fields(
        surface,
        {
            "minimum_instrumented_clients",
            "minimum_context_reduction_fraction",
            "maximum_task_success_regressions",
            "maximum_unsupported_claims",
            "specialist_access_required",
            "otherwise",
        },
        "surface_profile",
    )
    if _integer(surface["minimum_instrumented_clients"], "minimum_instrumented_clients") != 2:
        raise ContractError("surface decision must require at least two instrumented clients")
    reduction = surface["minimum_context_reduction_fraction"]
    if isinstance(reduction, bool) or not isinstance(reduction, (int, float)) or reduction != 0.30:
        raise ContractError("surface context-reduction threshold must remain 0.30")
    if _integer(surface["maximum_task_success_regressions"], "surface_task_regressions") != 0:
        raise ContractError("surface profile permits no task-success regression")
    if _integer(surface["maximum_unsupported_claims"], "surface_unsupported_claims") != 0:
        raise ContractError("surface profile permits no unsupported claims")
    if not _boolean(surface["specialist_access_required"], "specialist_access_required"):
        raise ContractError("surface profile must preserve specialist access")
    if _text(surface["otherwise"], "surface.otherwise") != "defer":
        raise ContractError("surface decision must fail closed to defer")


def _validate_decisions(payload: dict[str, object]) -> None:
    decisions = _mapping(payload["decisions"], "decisions")
    _exact_fields(decisions, {"portable_promotion", "surface_profile", "stop_rules"}, "decisions")
    _validate_portable_decision(decisions)
    _validate_surface_decision(decisions)
    _string_list(decisions["stop_rules"], "decisions.stop_rules")


def _validate_privacy(payload: dict[str, object]) -> None:
    privacy = _mapping(payload["privacy"], "privacy")
    _exact_fields(
        privacy,
        {
            "reserved_domains_only",
            "transcripts_public",
            "hidden_reasoning_public",
            "credentials_allowed",
            "local_output_root",
            "public_outputs",
        },
        "privacy",
    )
    if not _boolean(privacy["reserved_domains_only"], "reserved_domains_only"):
        raise ContractError("evaluation prompts must remain reserved-domain only")
    for false_field in ("transcripts_public", "hidden_reasoning_public", "credentials_allowed"):
        if _boolean(privacy[false_field], false_field):
            raise ContractError(f"privacy.{false_field} must remain false")
    output_root = ROOT / _text(privacy["local_output_root"], "local_output_root")
    try:
        output_root.resolve().relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ContractError("local output root must remain inside the repository") from exc
    if output_root != ROOT / "validation" / "agent-portability-local":
        raise ContractError("local output root has drifted")
    public_outputs = _string_list(privacy["public_outputs"], "public_outputs")
    if any("transcript" in item.lower() or "reasoning" in item.lower() for item in public_outputs):
        raise ContractError("public outputs must not include transcripts or hidden reasoning")


def validate_contract(payload: dict[str, object]) -> str:
    """Validate the contract and return its verified canonical digest."""

    _exact_fields(payload, _ROOT_FIELDS, "contract")
    if _integer(payload["schema_version"], "schema_version") != 1:
        raise ContractError("schema_version must be 1")
    if _text(payload["status"], "status") != "frozen":
        raise ContractError("contract status must be frozen")
    if _boolean(payload["private"], "private"):
        raise ContractError("the contract is a disclosure-safe public artifact")
    if _text(payload["round_id"], "round_id") != "agent-portability-v2.15-20260814":
        raise ContractError("round_id has drifted")
    frozen_at = _text(payload["frozen_at"], "frozen_at")
    try:
        parsed = datetime.fromisoformat(frozen_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("frozen_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.astimezone(UTC).date().isoformat() != "2026-08-14":
        raise ContractError("frozen_at must remain on the declared UTC review date")

    _validate_standard_snapshot(_mapping(payload["standards"], "standards"))
    _validate_selection(payload)
    _validate_clients(payload)
    _validate_tasks(payload)
    _validate_variants_and_failures(payload)
    _validate_measures(payload)
    _validate_decisions(payload)
    _validate_privacy(payload)

    declared = _text(payload["contract_digest_sha256"], "contract_digest_sha256")
    if not _HEX_SHA256.fullmatch(declared):
        raise ContractError("contract_digest_sha256 must be lowercase SHA-256")
    computed = canonical_digest(payload)
    if declared != computed:
        raise ContractError(f"contract digest mismatch: declared={declared}, computed={computed}")
    return computed


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, object]:
    """Load a bounded JSON contract from disk."""

    resolved = path.resolve()
    if not resolved.is_file():
        raise ContractError("contract path must name a regular file")
    size = resolved.stat().st_size
    if size <= 0 or size > MAX_CONTRACT_BYTES:
        raise ContractError(f"contract size must be between 1 and {MAX_CONTRACT_BYTES} bytes")
    try:
        payload: object = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"could not read contract: {exc}") from exc
    return _mapping(payload, "contract")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    args = parser.parse_args(argv)
    try:
        payload = load_contract(args.contract)
        digest = validate_contract(payload)
    except ContractError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    print(
        "PASS: frozen v2.15 agent-portability contract "
        f"digest={digest} clients={len(_CLIENT_IDS)} tasks={len(_TASK_IDS)} "
        f"sessions={len(_CLIENT_IDS) * len(_TASK_IDS) * len(_VARIANT_IDS)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
