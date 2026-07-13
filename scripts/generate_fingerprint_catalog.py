#!/usr/bin/env python3
"""Generate the deterministic built-in fingerprint runtime artifact."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

from recon_tool.exit_codes import EXIT_SUCCESS
from recon_tool.fingerprint_artifact import ArtifactSource, serialize_artifact_sources
from recon_tool.fingerprint_validator import validate_path

_ROOT = Path(__file__).resolve().parent.parent
_SOURCE_DIR = _ROOT / "src" / "recon_tool" / "data" / "fingerprints"
_ARTIFACT = _ROOT / "src" / "recon_tool" / "data" / "fingerprints.generated.json"


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(_ROOT).as_posix()
    except ValueError:
        return str(path)


def _raw_fingerprints(path: Path) -> tuple[dict[str, Any], ...]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"failed to read {path}: {exc}") from exc
    if isinstance(loaded, dict):
        raw = loaded.get("fingerprints")
    elif isinstance(loaded, list):
        raw = loaded
    else:
        raw = None
    if not isinstance(raw, list) or not all(isinstance(entry, dict) for entry in raw):
        raise ValueError(f"{path} must contain an array of fingerprint objects")
    return tuple(raw)


def build_artifact(source_dir: Path) -> str:
    """Validate the canonical YAML directory and return canonical JSON text."""
    if validate_path(source_dir, quiet=True) != EXIT_SUCCESS:
        raise ValueError(f"canonical fingerprint validation failed for {source_dir}")
    paths = sorted(source_dir.glob("*.yaml"))
    if not paths:
        raise ValueError(f"no canonical fingerprint YAML files found in {source_dir}")
    sources = tuple(ArtifactSource(path=path.name, fingerprints=_raw_fingerprints(path)) for path in paths)
    return serialize_artifact_sources(sources)


def _check_artifact(path: Path, generated: bytes) -> bool:
    try:
        current = path.read_bytes()
    except OSError as exc:
        print(f"FAIL {_display_path(path)} is unavailable: {exc}", file=sys.stderr)
        return False
    if current == generated:
        print(f"PASS {_display_path(path)} is current.")
        return True
    print(
        f"FAIL {_display_path(path)} is stale; run scripts/generate_fingerprint_catalog.py --write.",
        file=sys.stderr,
    )
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=_SOURCE_DIR, help="Canonical split-YAML directory.")
    parser.add_argument("--output", type=Path, default=_ARTIFACT, help="Generated JSON artifact path.")
    parser.add_argument("--check", action="store_true", help="Fail if the committed artifact is stale.")
    parser.add_argument("--write", action="store_true", help="Write the generated artifact.")
    parser.add_argument("--stdout", action="store_true", help="Print the generated artifact.")
    args = parser.parse_args(argv)
    selected_modes = sum((args.check, args.write, args.stdout))
    if selected_modes > 1:
        parser.error("--check, --write, and --stdout are mutually exclusive")
    try:
        generated_text = build_artifact(args.source_dir)
    except ValueError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    generated = generated_text.encode("utf-8")
    if args.check:
        return 0 if _check_artifact(args.output, generated) else 1
    if args.stdout or selected_modes == 0:
        print(generated_text, end="")
        return 0
    try:
        current = args.output.read_bytes() if args.output.exists() else None
        if current == generated:
            print(f"{_display_path(args.output)} already current.")
            return 0
        args.output.write_bytes(generated)
    except OSError as exc:
        print(f"FAIL could not write {_display_path(args.output)}: {exc}", file=sys.stderr)
        return 1
    print(f"Updated {_display_path(args.output)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
