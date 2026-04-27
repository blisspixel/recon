#!/usr/bin/env python
"""Validate fingerprint YAML files.

Usage:
    python scripts/validate_fingerprint.py <path>

The implementation lives in ``recon_tool.fingerprint_validator`` so the
installed ``recon fingerprints check`` command works from wheels as well as
from a source checkout.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))

    from recon_tool.fingerprint_validator import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_main())
