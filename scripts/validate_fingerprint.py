#!/usr/bin/env python
"""Validate fingerprint YAML files.

Loads each file, runs the same validation used at runtime
(``recon_tool.fingerprints._validate_fingerprint``), and reports pass/fail
per entry. Detects duplicate slugs within and across files when ``path``
is a directory. Exits 0 when every entry validates and no duplicates are
found, non-zero otherwise.

Used locally by contributors before opening a PR and by CI on any PR that
touches ``data/fingerprints.yaml``, ``data/fingerprints/``, or a custom
``~/.recon/fingerprints.yaml``.

Usage:
    python scripts/validate_fingerprint.py <path>

``<path>`` may be a single YAML file or a directory. When a directory is
given, every ``*.yaml`` file in it (non-recursive) is validated and all
entries are pooled for a cross-file duplicate-slug check.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

import yaml

from recon_tool.fingerprints import _validate_fingerprint  # pyright: ignore[reportPrivateUsage]


def _extract_entries(raw: Any, path: Path) -> list[Any] | None:
    """Accept wrapped ``{fingerprints: [...]}`` or bare list. None on shape error."""
    if isinstance(raw, dict) and "fingerprints" in raw:
        entries = raw["fingerprints"]
    elif isinstance(raw, list):
        entries = raw
    else:
        print(
            f"error: {path} must be either a list of fingerprints or a dict with a 'fingerprints' key",
            file=sys.stderr,
        )
        return None
    if not isinstance(entries, list):
        print(f"error: 'fingerprints' key in {path} must be a list", file=sys.stderr)
        return None
    return entries


def _validate_file(
    path: Path,
    *,
    quiet: bool,
    captured: list[logging.LogRecord],
    slug_sources: dict[str, list[Path]],
) -> tuple[int, int, list[str]]:
    """Validate one file. Returns (total, passed, failed_names)."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        print(f"error: invalid YAML in {path}: {exc}", file=sys.stderr)
        return (0, 0, [f"{path} (YAML parse)"])

    entries = _extract_entries(raw, path)
    if entries is None:
        return (0, 0, [f"{path} (shape)"])

    total = 0
    passed = 0
    failed_names: list[str] = []

    for idx, entry in enumerate(entries):
        total += 1
        before = len(captured)
        name: str | Any = "<unknown>"
        if isinstance(entry, dict):
            name = entry.get("name", f"<index {idx}>")
            slug = entry.get("slug")
            if isinstance(slug, str) and slug:
                slug_sources.setdefault(slug, []).append(path)
        result = _validate_fingerprint(entry if isinstance(entry, dict) else {}, str(path))
        warnings_this_entry = captured[before:]

        if result is not None and not warnings_this_entry:
            passed += 1
            if not quiet:
                print(f"ok    {path.name}: {name}")
        else:
            failed_names.append(f"{path.name}: {name}")
            print(f"FAIL  {path.name}: {name}", file=sys.stderr)
            for w in warnings_this_entry:
                print(f"      {w.getMessage()}", file=sys.stderr)
            if result is None and not warnings_this_entry:
                print("      (validation returned None — see earlier output)", file=sys.stderr)

    return (total, passed, failed_names)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate fingerprint YAML files against recon's runtime schema "
            "(regex safety, required fields, detection types, weight range, match_mode). "
            "When <path> is a directory, all *.yaml files are validated and slugs are "
            "pooled for a cross-file duplicate-slug check."
        )
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to a fingerprints YAML file or a directory of fingerprint files",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-entry success messages; only print failures and summary",
    )
    args = parser.parse_args(argv)

    if not args.path.exists():
        print(f"error: {args.path} does not exist", file=sys.stderr)
        return 2

    captured: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    recon_logger = logging.getLogger("recon")
    handler = _Capture()
    handler.setLevel(logging.WARNING)
    recon_logger.addHandler(handler)
    recon_logger.setLevel(logging.WARNING)

    slug_sources: dict[str, list[Path]] = {}
    total = 0
    passed = 0
    failed_names: list[str] = []

    if args.path.is_dir():
        files = sorted(args.path.glob("*.yaml"))
        if not files:
            print(f"error: no *.yaml files found in {args.path}", file=sys.stderr)
            return 2
        for f in files:
            t, p, fails = _validate_file(f, quiet=args.quiet, captured=captured, slug_sources=slug_sources)
            total += t
            passed += p
            failed_names.extend(fails)
    else:
        total, passed, failed_names = _validate_file(
            args.path, quiet=args.quiet, captured=captured, slug_sources=slug_sources
        )

    # Cross-file duplicate-slug detection (works even for single-file mode —
    # duplicates within one file still count).
    duplicates = {slug: paths for slug, paths in slug_sources.items() if len(paths) > 1}

    print()
    print(f"Validated {total} entries: {passed} passed, {len(failed_names)} failed")
    if duplicates:
        print(f"Duplicate slugs: {len(duplicates)}", file=sys.stderr)
        for slug, paths in sorted(duplicates.items()):
            unique = sorted({str(p) for p in paths})
            print(f"  {slug}: {', '.join(unique)}", file=sys.stderr)
    if failed_names:
        print(f"Failed: {', '.join(failed_names)}", file=sys.stderr)
    if failed_names or duplicates:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
