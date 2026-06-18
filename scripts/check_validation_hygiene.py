#!/usr/bin/env python3
"""Guard committed validation artifacts against target-data leaks."""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PRIVATE_PREFIXES = (
    "validation/corpus-private/",
    "validation/runs-private/",
    "validation/local/",
    "validation/live_runs/",
    "validation/agentic_ux/runs/",
    "validation/agentic_ux/local/",
)

ROOT_DUMP_SUFFIXES = (
    ".com.json",
    ".org.json",
    ".net.json",
    ".io.json",
    ".so.json",
    ".gov.json",
    ".edu.json",
    ".co.json",
)

SCAN_SUFFIXES = {".csv", ".json", ".md", ".ndjson", ".txt", ".yaml", ".yml"}
CONTENT_SKIP_PREFIXES = (
    "validation/aggregate/",
    "validation/agentic_ux/fixtures/",
    "validation/synthetic_corpus/",
)

ALLOWED_DOMAINS = {
    "adventure-works.com",
    "contoso.com",
    "example.com",
    "example.net",
    "example.org",
    "fabrikam.com",
    "northwindtraders.com",
    "tailspintoys.com",
    "wideworldimporters.com",
    "wingtiptoys.com",
}

DOMAIN_RE = re.compile(r"(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{2,})+\b")
TARGET_FIELD_RE = re.compile(
    r"(?i)\b(?:apex|apex_domain|default_domain|domain|input_domain|queried_domain)\b"
    r"\s*[:=]\s*[\"'`]?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})[\"'`]?"
)
RECON_COMMAND_RE = re.compile(r"(?i)\brecon\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b")


@dataclass(frozen=True)
class Violation:
    path: str
    detail: str
    line: int | None = None

    def render(self) -> str:
        location = self.path if self.line is None else f"{self.path}:{self.line}"
        return f"{location}: {self.detail}"


def _tracked_files(root: Path = ROOT) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],  # noqa: S607 - fixed developer-tool argv
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        msg = result.stderr.strip() or "git ls-files failed"
        raise RuntimeError(msg)
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]


def _is_allowed_domain(domain: str) -> bool:
    normalized = domain.lower().strip(".")
    if normalized.endswith((".test", ".invalid")):
        return True
    return normalized in ALLOWED_DOMAINS or any(normalized.endswith(f".{allowed}") for allowed in ALLOWED_DOMAINS)


def _looks_like_domain_line(line: str) -> str | None:
    stripped = line.strip().strip('"').strip("'").strip("`")
    if not stripped or stripped.startswith("#"):
        return None
    return stripped.lower() if DOMAIN_RE.fullmatch(stripped) else None


def _should_scan_content(path: str) -> bool:
    if not path.startswith("validation/"):
        return False
    if path.startswith(CONTENT_SKIP_PREFIXES):
        return False
    return Path(path).suffix.lower() in SCAN_SUFFIXES


def _path_violations(paths: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    for path in paths:
        if path.startswith(PRIVATE_PREFIXES):
            violations.append(Violation(path, "private validation corpus or run output is tracked"))
        if "/" not in path and path.endswith(ROOT_DUMP_SUFFIXES):
            violations.append(Violation(path, "root per-domain JSON dump is tracked"))
    return violations


def _content_violations(root: Path, paths: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    for path in paths:
        if not _should_scan_content(path):
            continue
        full_path = root / path
        if not full_path.exists():
            continue
        try:
            lines = full_path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        scan_exact_lines = Path(path).suffix.lower() in {".csv", ".txt"}
        for index, line in enumerate(lines, start=1):
            field_match = TARGET_FIELD_RE.search(line)
            if field_match is not None and not _is_allowed_domain(field_match.group(1)):
                violations.append(
                    Violation(path, f"target-domain field is not fictional or reserved: {field_match.group(1)}", index)
                )
            command_match = RECON_COMMAND_RE.search(line)
            if command_match is not None and not _is_allowed_domain(command_match.group(1)):
                violations.append(
                    Violation(path, f"recon example uses a non-fictional domain: {command_match.group(1)}", index)
                )
            domain_line = _looks_like_domain_line(line) if scan_exact_lines else None
            if domain_line is not None and not _is_allowed_domain(domain_line):
                violations.append(Violation(path, f"corpus line is not fictional or reserved: {domain_line}", index))
    return violations


def find_violations(root: Path = ROOT, paths: list[str] | None = None) -> list[Violation]:
    tracked = paths if paths is not None else _tracked_files(root)
    normalized = [path.replace("\\", "/") for path in tracked]
    return [*_path_violations(normalized), *_content_violations(root, normalized)]


def main() -> int:
    violations = find_violations()
    if violations:
        print("Validation hygiene failed:")
        for violation in violations:
            print(f"  {violation.render()}")
        print("")
        print("Keep real apexes, per-domain outputs, and private run artifacts local.")
        print("Commit only synthetic examples or aggregate validation statistics.")
        return 1
    print("OK: no tracked private validation artifacts or target-domain validation fields.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
