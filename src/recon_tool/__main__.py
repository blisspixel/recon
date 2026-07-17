"""Allow ``python -m recon_tool`` to invoke the CLI entry point."""

from __future__ import annotations

from recon_tool.cli import run

if __name__ == "__main__":
    run()
