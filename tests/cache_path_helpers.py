"""Cross-platform filesystem redirect fixtures for cache containment tests."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def self_referencing_directory(path: Path) -> Generator[None]:
    """Create and reliably remove a self-referencing symlink or junction."""
    if os.name == "nt":
        command_processor = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
        subprocess.run(  # noqa: S603 - controlled test-only path creates a local junction
            [command_processor, "/d", "/c", "mklink", "/J", str(path), str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        path.symlink_to(path, target_is_directory=True)
    try:
        yield
    finally:
        if os.name == "nt":
            path.rmdir()
        else:
            path.unlink()
