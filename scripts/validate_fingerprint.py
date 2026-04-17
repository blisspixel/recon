#!/usr/bin/env python
"""Validate a fingerprints YAML file.

Loads the file, runs the same validation used at runtime
(recon_tool.fingerprints._validate_fingerprint), and reports pass/fail per
entry. Exits 0 when every entry validates, non-zero otherwise.

Used locally by contributors before opening a PR and by CI on any PR that
touches data/fingerprints.yaml or a custom fingerprints.yaml.

Usage:
    python scripts/validate_fingerprint.py <path-to-yaml>
    python scripts/validate_fingerprint.py recon_tool/data/fingerprints.yaml
    python scripts/validate_fingerprint.py ~/.recon/fingerprints.yaml
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

import yaml

from recon_tool.fingerprints import _validate_fingerprint  # pyright: ignore[reportPrivateUsage]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a fingerprints YAML file against recon's runtime schema "
            "(regex safety, required fields, detection types, weight range, match_mode)."
        )
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to the fingerprints YAML file",
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

    try:
        raw = yaml.safe_load(args.path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        print(f"error: invalid YAML in {args.path}: {exc}", file=sys.stderr)
        return 2

    # Accept both the wrapped format ({fingerprints: [...]}) and a bare list.
    if isinstance(raw, dict) and "fingerprints" in raw:
        entries = raw["fingerprints"]
    elif isinstance(raw, list):
        entries = raw
    else:
        print(
            f"error: {args.path} must be either a list of fingerprints or "
            "a dict with a 'fingerprints' key",
            file=sys.stderr,
        )
        return 2

    if not isinstance(entries, list):
        print(f"error: 'fingerprints' key in {args.path} must be a list", file=sys.stderr)
        return 2

    # Capture warnings from _validate_fingerprint so we can surface them nicely
    captured: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    recon_logger = logging.getLogger("recon")
    handler = _Capture()
    handler.setLevel(logging.WARNING)
    recon_logger.addHandler(handler)
    recon_logger.setLevel(logging.WARNING)

    total = 0
    passed = 0
    failed_names: list[str] = []

    for idx, entry in enumerate(entries):
        total += 1
        before = len(captured)
        name: str | Any = "<unknown>"
        if isinstance(entry, dict):
            name = entry.get("name", f"<index {idx}>")
        result = _validate_fingerprint(entry if isinstance(entry, dict) else {}, str(args.path))
        warnings_this_entry = captured[before:]

        if result is not None and not warnings_this_entry:
            passed += 1
            if not args.quiet:
                print(f"ok    {name}")
        else:
            failed_names.append(str(name))
            print(f"FAIL  {name}", file=sys.stderr)
            for w in warnings_this_entry:
                print(f"      {w.getMessage()}", file=sys.stderr)
            if result is None and not warnings_this_entry:
                print("      (validation returned None — see earlier output)", file=sys.stderr)

    print()
    print(f"Validated {total} entries: {passed} passed, {len(failed_names)} failed")
    if failed_names:
        print(f"Failed: {', '.join(failed_names)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
