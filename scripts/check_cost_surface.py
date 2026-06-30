#!/usr/bin/env python3
"""Guard the zero-paid-API runtime and automation invariant."""

from __future__ import annotations

import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PYPROJECT = ROOT / "pyproject.toml"
RUNTIME_DIR = ROOT / "src" / "recon_tool"
SCRIPT_DIR = ROOT / "scripts"
WORKFLOW_DIR = ROOT / ".github" / "workflows"

EXPECTED_WHEEL_PACKAGES = ("src/recon_tool",)

FORBIDDEN_RUNTIME_DEPENDENCIES = {
    "anthropic",
    "azure-ai-openai",
    "azure-identity",
    "boto3",
    "botocore",
    "fal-client",
    "google-cloud-aiplatform",
    "google-genai",
    "google-generativeai",
    "huggingface-hub",
    "openai",
    "replicate",
    "stability-sdk",
    "stripe",
    "xai-sdk",
}

FORBIDDEN_EXECUTION_MARKERS = {
    "ANTHROPIC_API_KEY": "paid model provider key",
    "OPENAI_API_KEY": "paid model provider key",
    "XAI_API_KEY": "paid model provider key",
    "api.anthropic.com": "paid model provider endpoint",
    "api.openai.com": "paid model provider endpoint",
    "api.x.ai": "paid model provider endpoint",
    "anthropic.Anthropic": "paid model provider SDK client",
    "openai.OpenAI": "paid model provider SDK client",
    "chat.completions.create": "paid model provider chat call",
    "client.images": "paid image API client",
    "images.generate": "paid image generation call",
    "responses.create": "paid model provider response call",
    "replicate.run": "paid model provider execution call",
}

FORBIDDEN_WORKFLOW_MARKERS = {
    **FORBIDDEN_EXECUTION_MARKERS,
    "validation.agentic_ux.run": "manual paid validation harness invoked from workflow",
    "validation/agentic_ux/run.py": "manual paid validation harness invoked from workflow",
    "--provider anthropic": "manual paid validation provider invoked from workflow",
    "--provider openai": "manual paid validation provider invoked from workflow",
    "--provider xai": "manual paid validation provider invoked from workflow",
}

DEPENDENCY_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)")


@dataclass(frozen=True)
class Violation:
    path: str
    detail: str
    line: int | None = None

    def render(self) -> str:
        location = self.path if self.line is None else f"{self.path}:{self.line}"
        return f"{location}: {self.detail}"


def _repo_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _project_data(root: Path) -> dict[str, object]:
    return tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))


def _dependency_name(requirement: str) -> str:
    match = DEPENDENCY_NAME_RE.match(requirement)
    return match.group(1).lower().replace("_", "-") if match else requirement.lower()


def _nested_table(data: object, keys: tuple[str, ...]) -> dict[str, object] | None:
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current if isinstance(current, dict) else None


def _iter_files(paths: tuple[Path, ...], suffixes: set[str]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix.lower() in suffixes:
            files.append(path)
        elif path.is_dir():
            files.extend(file for file in path.rglob("*") if file.is_file() and file.suffix.lower() in suffixes)
    return sorted(files)


def _scan_file(path: Path, root: Path, markers: dict[str, str]) -> list[Violation]:
    violations: list[Violation] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return violations
    for line_number, line in enumerate(lines, start=1):
        for marker, reason in markers.items():
            if marker in line:
                violations.append(Violation(_repo_path(path, root), f"{reason}: {marker}", line_number))
    return violations


def _dependency_violations(root: Path) -> list[Violation]:
    data = _project_data(root)
    project = data.get("project", {})
    if not isinstance(project, dict):
        return [Violation("pyproject.toml", "missing [project] table")]
    raw_dependencies = project.get("dependencies", [])
    if not isinstance(raw_dependencies, list):
        return [Violation("pyproject.toml", "[project].dependencies must be a list")]

    violations: list[Violation] = []
    for dependency in raw_dependencies:
        if not isinstance(dependency, str):
            violations.append(Violation("pyproject.toml", "runtime dependency entry must be a string"))
            continue
        name = _dependency_name(dependency)
        if name in FORBIDDEN_RUNTIME_DEPENDENCIES:
            violations.append(
                Violation("pyproject.toml", f"runtime dependency can reach a paid or credentialed API: {dependency}")
            )
    return violations


def _wheel_package_violations(root: Path) -> list[Violation]:
    violations: list[Violation] = []
    wheel = _nested_table(_project_data(root), ("tool", "hatch", "build", "targets", "wheel"))
    if wheel is None:
        violations.append(Violation("pyproject.toml", "missing [tool.hatch.build.targets.wheel] table"))
    else:
        raw_packages = wheel.get("packages", [])
        if isinstance(raw_packages, list):
            packages = tuple(package for package in raw_packages if isinstance(package, str))
        else:
            packages = ()
        if packages != EXPECTED_WHEEL_PACKAGES:
            expected = ", ".join(EXPECTED_WHEEL_PACKAGES)
            violations.append(
                Violation("pyproject.toml", f"wheel packages must stay limited to {expected}; found {raw_packages!r}")
            )
    return violations


def _execution_marker_violations(root: Path) -> list[Violation]:
    scanned = _iter_files((root / "src" / "recon_tool", root / "scripts"), {".py", ".ps1", ".sh"})
    scanned = [path for path in scanned if path.resolve() != (root / "scripts" / "check_cost_surface.py").resolve()]
    return [violation for path in scanned for violation in _scan_file(path, root, FORBIDDEN_EXECUTION_MARKERS)]


def _workflow_violations(root: Path) -> list[Violation]:
    scanned = _iter_files((root / ".github" / "workflows",), {".yml", ".yaml"})
    return [violation for path in scanned for violation in _scan_file(path, root, FORBIDDEN_WORKFLOW_MARKERS)]


def find_violations(root: Path = ROOT) -> list[Violation]:
    return [
        *_dependency_violations(root),
        *_wheel_package_violations(root),
        *_execution_marker_violations(root),
        *_workflow_violations(root),
    ]


def main() -> int:
    violations = find_violations()
    if violations:
        print("Cost-surface check failed:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation.render()}", file=sys.stderr)
        print("", file=sys.stderr)
        print(
            "Keep paid-provider SDKs, keys, and validation-only paid harnesses out of runtime and workflows.",
            file=sys.stderr,
        )
        return 1
    print("OK: runtime, wheel packaging, dependencies, and workflows expose no paid-provider cost surface.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
