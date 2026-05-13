"""Validate fingerprint YAML files against recon's runtime schema."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

import yaml

from recon_tool.fingerprints import _validate_fingerprint  # pyright: ignore[reportPrivateUsage]
from recon_tool.specificity import evaluate_pattern

__all__ = ["main", "validate_path"]


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
    skip_specificity: bool,
    captured: list[logging.LogRecord],
    slug_sources: dict[str, list[Path]],
    slug_names: dict[str, set[str]],
    specificity_warnings: list[str],
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
                if isinstance(name, str):
                    slug_names.setdefault(slug, set()).add(name)
        result = _validate_fingerprint(entry if isinstance(entry, dict) else {}, str(path))
        warnings_this_entry = captured[before:]

        specificity_fails: list[str] = []
        if not skip_specificity and result is not None:
            for det in result.detections:
                verdict = evaluate_pattern(det.pattern, det.type)
                if verdict.threshold_exceeded:
                    msg = (
                        f"over-broad pattern: type={det.type!r} "
                        f"pattern={det.pattern!r} matched {verdict.matches}/"
                        f"{verdict.corpus_size} of the synthetic corpus "
                        f"({verdict.match_rate:.1%} > "
                        f"{0.01:.0%} threshold)"
                    )
                    specificity_fails.append(msg)

        if result is not None and not warnings_this_entry and not specificity_fails:
            passed += 1
            if not quiet:
                print(f"ok    {path.name}: {name}")
        else:
            failed_names.append(f"{path.name}: {name}")
            print(f"FAIL  {path.name}: {name}", file=sys.stderr)
            for warning in warnings_this_entry:
                print(f"      {warning.getMessage()}", file=sys.stderr)
            for specificity_fail in specificity_fails:
                print(f"      {specificity_fail}", file=sys.stderr)
                specificity_warnings.append(f"{path.name}: {name}: {specificity_fail}")
            if result is None and not warnings_this_entry and not specificity_fails:
                print("      (validation returned None - see earlier output)", file=sys.stderr)

    return (total, passed, failed_names)


def validate_path(path: Path, *, quiet: bool = False, skip_specificity: bool = False) -> int:
    """Validate a fingerprint YAML file or directory and return a process exit code."""
    if not path.exists():
        print(f"error: {path} does not exist", file=sys.stderr)
        return 2

    captured: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    recon_logger = logging.getLogger("recon")
    handler = _Capture()
    handler.setLevel(logging.WARNING)
    recon_logger.addHandler(handler)
    previous_level = recon_logger.level
    recon_logger.setLevel(logging.WARNING)

    try:
        return _validate_path_with_capture(
            path,
            quiet=quiet,
            skip_specificity=skip_specificity,
            captured=captured,
        )
    finally:
        recon_logger.removeHandler(handler)
        recon_logger.setLevel(previous_level)


def _validate_path_with_capture(
    path: Path,
    *,
    quiet: bool,
    skip_specificity: bool,
    captured: list[logging.LogRecord],
) -> int:
    slug_sources: dict[str, list[Path]] = {}
    slug_names: dict[str, set[str]] = {}
    specificity_warnings: list[str] = []
    total = 0
    passed = 0
    failed_names: list[str] = []

    if path.is_dir():
        files = sorted(path.glob("*.yaml"))
        if not files:
            print(f"error: no *.yaml files found in {path}", file=sys.stderr)
            return 2
        for file_path in files:
            file_total, file_passed, file_failures = _validate_file(
                file_path,
                quiet=quiet,
                skip_specificity=skip_specificity,
                captured=captured,
                slug_sources=slug_sources,
                slug_names=slug_names,
                specificity_warnings=specificity_warnings,
            )
            total += file_total
            passed += file_passed
            failed_names.extend(file_failures)
    else:
        total, passed, failed_names = _validate_file(
            path,
            quiet=quiet,
            skip_specificity=skip_specificity,
            captured=captured,
            slug_sources=slug_sources,
            slug_names=slug_names,
            specificity_warnings=specificity_warnings,
        )

    # A slug appearing in multiple files is a *real* duplicate only when the
    # display names disagree. Same slug + same name across files is the
    # legitimate "split detection rules across files" pattern (e.g. surface.yaml
    # extends an apex fingerprint with cname_target rules under the same slug
    # and name). Real duplicates flag two distinct services colliding on a slug.
    duplicates = {
        slug: paths for slug, paths in slug_sources.items() if len(paths) > 1 and len(slug_names.get(slug, set())) > 1
    }

    print()
    print(f"Validated {total} entries: {passed} passed, {len(failed_names)} failed")
    if duplicates:
        print(f"Duplicate slugs: {len(duplicates)}", file=sys.stderr)
        for slug, paths in sorted(duplicates.items()):
            names = ", ".join(sorted(slug_names.get(slug, set())))
            locations = ", ".join(str(path_item) for path_item in paths)
            print(f"  {slug}: names=[{names}] in {locations}", file=sys.stderr)

    if specificity_warnings and not quiet:
        print()
        print("Specificity failures:")
        for warning in specificity_warnings:
            print(f"  - {warning}")

    if failed_names or duplicates:
        return 1
    return 0


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
    parser.add_argument(
        "--skip-specificity",
        action="store_true",
        help=(
            "Disable the specificity gate (matches each regex against a "
            "synthetic adversarial corpus and rejects over-broad patterns). "
            "Off by default because we want contributors to pass the gate."
        ),
    )
    args = parser.parse_args(argv)
    return validate_path(args.path, quiet=args.quiet, skip_specificity=args.skip_specificity)


if __name__ == "__main__":
    raise SystemExit(main())
