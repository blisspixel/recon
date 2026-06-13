#!/usr/bin/env python3
"""Refresh the Homebrew formula's url + sha256 from the latest PyPI release.

The formula (``packaging/homebrew/recon.rb``) pins the sdist URL and its sha256;
Homebrew derives the version from the URL filename, so those two lines are the
only per-release churn. Run this after a release lands on PyPI:

    python scripts/update_homebrew_formula.py          # update to latest
    python scripts/update_homebrew_formula.py 2.2.0    # update to a specific version
    python scripts/update_homebrew_formula.py --check   # verify it's current (CI/release gate)

Exit 0 on success (or already-current with --check); non-zero if the formula
would change under --check, or on any fetch/parse error. Network-only against
pypi.org; no credentials.
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path

_PACKAGE = "recon-tool"
_FORMULA = Path(__file__).resolve().parent.parent / "packaging" / "homebrew" / "recon.rb"
_URL_RE = re.compile(r'^(\s*url\s+")[^"]*(")', re.MULTILINE)
_SHA_RE = re.compile(r'^(\s*sha256\s+")[0-9a-f]{64}(")', re.MULTILINE)


def _fetch_sdist(version: str | None) -> tuple[str, str, str]:
    """Return (resolved_version, sdist_url, sha256) for the PyPI release."""
    with urllib.request.urlopen(f"https://pypi.org/pypi/{_PACKAGE}/json", timeout=30) as resp:
        data = json.load(resp)
    resolved = version or data["info"]["version"]
    files = data["releases"].get(resolved, [])
    sdist = next((f for f in files if f["packagetype"] == "sdist"), None)
    if sdist is None:
        raise SystemExit(f"no sdist found on PyPI for {_PACKAGE} {resolved}")
    return resolved, sdist["url"], sdist["digests"]["sha256"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh the Homebrew formula from PyPI.")
    parser.add_argument("version", nargs="?", help="Specific version (default: latest on PyPI).")
    parser.add_argument("--check", action="store_true", help="Fail if the formula is not already current.")
    args = parser.parse_args(argv)

    resolved, url, sha = _fetch_sdist(args.version)
    original = _FORMULA.read_text(encoding="utf-8")
    updated = _SHA_RE.sub(rf"\g<1>{sha}\g<2>", _URL_RE.sub(rf"\g<1>{url}\g<2>", original))

    if updated == original:
        print(f"Homebrew formula already current for {_PACKAGE} {resolved}.")
        return 0
    if args.check:
        print(f"FAIL: Homebrew formula is stale; run scripts/update_homebrew_formula.py (target {resolved}).")
        return 1
    _FORMULA.write_text(updated, encoding="utf-8")
    print(f"Updated {_FORMULA.name} to {_PACKAGE} {resolved}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
