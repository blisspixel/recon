#!/usr/bin/env python3
"""Check exact legacy typing scopes and audit their still-visible diagnostics.

The audit runs the pinned checker on a temporary source copy with file-level
relaxations restored to errors. It never edits the checkout or executes copied
code. Existing inline negative-test and dependency exceptions remain explicit.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import TypedDict

from recon_tool.json_limits import is_json_object

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs/typing-exceptions.json"
_COPY_ROOTS = ("src/recon_tool", "tests", "scripts", "validation")
_INCLUDES = [
    "src/recon_tool",
    "tests",
    "validation/corpus_aggregator.py",
    "validation/drift_check.py",
    "validation/quality_arm_identifiability.py",
    "scripts/check_typing_policy.py",
    "validation/catalog_result_input.py",
]
_CONTROL = re.compile(r"(report\w+)\s*=\s*(?:none|false|warning|information)", re.IGNORECASE)
_DIRECTIVE = re.compile(r"^\s*#\s*pyright\s*:\s*(.*)")
_INLINE = re.compile(r"#\s*(?:pyright:\s*ignore|type:\s*ignore)(?:\[([^\]]+)\])?")
_PROTECTED = (
    "validation/catalog_result_input.py",
    "src/recon_tool/json_limits.py",
    "src/recon_tool/cache_admission.py",
    "src/recon_tool/fingerprint_artifact.py",
    "src/recon_tool/sources/oidc.py",
    "src/recon_tool/collection_limits.py",
    "src/recon_tool/sources/dns_base.py",
    "src/recon_tool/rate_limit.py",
    "tests/tenant_fixtures.py",
    "scripts/check_typing_policy.py",
)


class DiagnosticIdentity(TypedDict):
    count: int
    digest: str


class AuditResult(TypedDict):
    files_analyzed: int
    diagnostics: dict[str, dict[str, DiagnosticIdentity]]


def source_files(root: Path) -> list[Path]:
    """Copy Python source needed for import resolution, without private inputs."""
    return sorted(path for name in _COPY_ROOTS for path in (root / name).rglob("*.py"))


def checked_files(root: Path) -> list[Path]:
    """The authoritative configured scope, separately from import-only copies."""
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pyright"]
    return sorted(
        path
        for name in config["include"]
        for path in ((root / name).rglob("*.py") if (root / name).is_dir() else [root / name])
    )


def controls(root: Path) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Record exact per-file rule controls and content-bound inline exceptions."""
    files: dict[str, list[str]] = {}
    inline: dict[str, list[str]] = {}
    for path in checked_files(root):
        relative = path.relative_to(root).as_posix()
        rules: set[str] = set()
        markers: list[str] = []
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            directive = _DIRECTIVE.match(line)
            if directive:
                rules.update(_CONTROL.findall(line))
                for part in directive[1].split(","):
                    if part.strip() in ("basic", "off", "standard"):
                        rules.add("mode:" + part.strip())
            if _INLINE.search(line):
                context = line.strip()
                if line.lstrip().startswith("#"):
                    context += "\n" + next((part.strip() for part in lines[index + 1 :] if part.strip()), "")
                markers.append(hashlib.sha256(context.encode()).hexdigest())
        if rules:
            files[relative] = sorted(rules)
        if markers:
            inline[relative] = sorted(markers)
    return files, inline


def policy_problems(config: Mapping[str, object], ledger: Mapping[str, object], root: Path) -> list[str]:
    """Reject global relaxations, scope changes and unowned source exceptions."""
    problems: list[str] = []
    if config != ledger["configuration"]:
        problems.append("Pyright configuration differs from the reviewed policy")
    if config.get("include") != _INCLUDES or config.get("exclude") or config.get("ignore"):
        problems.append("configured source, test and selected-validation scope must remain complete")
    if config.get("typeCheckingMode") != "strict" or config.get("executionEnvironments"):
        problems.append("strict mode without execution-environment relaxations is required")
    if any(value in (False, "none", "warning") for key, value in config.items() if key.startswith("report")):
        problems.append("global diagnostic relaxations are forbidden")
    actual_files, actual_inline = controls(root)
    if actual_files != ledger["file_controls"]:
        problems.append("file-level typing controls differ from the owned exact-path inventory")
    if actual_inline != ledger["inline_controls"]:
        problems.append("inline typing exceptions differ from the reviewed content-bound inventory")
    ownership_raw = ledger.get("ownership", {})
    reasons_raw = ledger.get("reasons", {})
    ownership = ownership_raw if is_json_object(ownership_raw) else {}
    reasons = reasons_raw if is_json_object(reasons_raw) else {}
    for path, rules in actual_files.items():
        owned = ownership.get(path, {})
        if (
            not is_json_object(owned)
            or set(owned) != set(rules)
            or any(not isinstance(reason, str) or reason not in reasons for reason in owned.values())
        ):
            problems.append(f"missing exact rule ownership/revisit category: {path}")
    if actual_files and not ledger.get("owner"):
        problems.append("retained file exceptions require maintainer ownership")
    if any(rule.startswith("mode:") for rules in actual_files.values() for rule in rules):
        problems.append("file-level basic/off/standard modes are forbidden")
    for path in _PROTECTED:
        if path in actual_files:
            problems.append(f"repaired boundary must retain all diagnostic families: {path}")
    return problems


def _restore_diagnostics(text: str) -> str:
    lines = text.splitlines(keepends=True)
    return "".join(
        _CONTROL.sub(lambda match: f"{match[1]}=error", line) if _DIRECTIVE.match(line) else line for line in lines
    )


def audit(root: Path, *, diagnostics_output: Path | None = None) -> AuditResult:
    """Measure exceptions in isolation; relative includes must analyze real files."""
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pyright"]
    with tempfile.TemporaryDirectory(prefix="recon-typing-audit-") as directory:
        copied = Path(directory)
        checked = set(checked_files(root))
        for original in source_files(root):
            destination = copied / original.relative_to(root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            text = original.read_text(encoding="utf-8")
            destination.write_text(_restore_diagnostics(text) if original in checked else text, encoding="utf-8")
        for original in (root / "src").rglob("py.typed"):
            shutil.copyfile(original, copied / original.relative_to(root))
        config["venvPath"] = str(root)
        config["pythonPlatform"] = "Linux"
        (copied / "pyrightconfig.json").write_text(json.dumps(config), encoding="utf-8")
        result = subprocess.run(  # noqa: S603 - fixed interpreter/module, only a local temporary path varies.
            [sys.executable, "-m", "pyright", "--outputjson", "--project", str(copied)],
            cwd=copied,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if result.returncode not in (0, 1):
            raise RuntimeError(f"Pyright audit could not complete: {result.stderr}")
        data = json.loads(result.stdout)
        expected = len(checked)
        if data["summary"]["filesAnalyzed"] != expected:
            raise RuntimeError(f"Pyright audit analyzed the wrong scope: {data['summary']} (expected {expected})")
        grouped: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        details: list[dict[str, object]] = []
        for diagnostic in data["generalDiagnostics"]:
            if diagnostic["severity"] != "error":
                continue
            path = Path(diagnostic["file"])
            relative = path.relative_to(copied).as_posix()
            line_index: int = diagnostic["range"]["start"]["line"]
            line = path.read_text(encoding="utf-8").splitlines()[line_index].strip()
            # Context and messages identify existing debt without publishing
            # fixture literals or absolute workstation paths in the ledger.
            message = diagnostic["message"].replace(str(copied), "<checkout>").replace(str(root), "<checkout>")
            signature = hashlib.sha256(json.dumps([message, line], ensure_ascii=True).encode()).hexdigest()
            rule: str = diagnostic.get("rule", "unclassified")
            grouped[relative][rule].append(signature)
            if diagnostics_output is not None:
                details.append({"file": relative, "line": line_index + 1, "rule": rule, "message": message})
        diagnostics: dict[str, dict[str, DiagnosticIdentity]] = {
            path: {
                rule: {"count": len(values), "digest": hashlib.sha256("\n".join(sorted(values)).encode()).hexdigest()}
                for rule, values in sorted(rules.items())
            }
            for path, rules in sorted(grouped.items())
        }
        if diagnostics_output is not None:
            diagnostics_output.write_text(json.dumps(details, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        return {"files_analyzed": expected, "diagnostics": diagnostics}


def diagnostic_problems(actual: Mapping[str, object], ledger: Mapping[str, object]) -> list[str]:
    """Require review of any changed diagnostic, including same-count replacements."""
    previous = ledger.get("audit")
    if is_json_object(previous) and actual.get("diagnostics") == previous.get("diagnostics"):
        return []
    return ["legacy diagnostic identities changed; inspect the full audit and narrow/update the owned ledger"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audit-output", type=Path, help="Write current diagnostic identities for review, without changing policy"
    )
    parser.add_argument(
        "--diagnostics-output",
        type=Path,
        help="Write local unmasked errors with source paths/lines; keep this file private under .agent/",
    )
    args = parser.parse_args(argv)
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pyright"]
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    problems = policy_problems(config, ledger, ROOT)
    if importlib.metadata.version("pyright") != ledger["pyright_version"]:
        problems.append("typing policy requires the repository-pinned Pyright version")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    measured = audit(ROOT, diagnostics_output=args.diagnostics_output)
    if args.audit_output:
        args.audit_output.write_text(json.dumps(measured, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    problems.extend(diagnostic_problems(measured, ledger))
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    counts = Counter(rule for rules in measured["diagnostics"].values() for rule in rules)
    print(f"Typing policy: {measured['files_analyzed']} files; exact exceptions verified across {len(counts)} families")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
