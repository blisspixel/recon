#!/usr/bin/env python3
"""Guard the interface package-locality migration.

Implementation for CLI, formatter, MCP server, and MCP client code should live
inside local packages. The remaining top-level prefix modules are compatibility
shims for historical imports.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "src" / "recon_tool"
MAX_SHIM_LINES = 30

ALLOWED_SHIMS: dict[str, str] = {
    "cli_batch.py": "recon_tool.cli.batch",
    "cli_cache.py": "recon_tool.cli.cache",
    "cli_doctor.py": "recon_tool.cli.doctor",
    "cli_fingerprints.py": "recon_tool.cli.fingerprints",
    "cli_lookup.py": "recon_tool.cli.lookup",
    "cli_mcp.py": "recon_tool.cli.mcp",
    "cli_shared.py": "recon_tool.cli.shared",
    "cli_signals.py": "recon_tool.cli.signals",
    "client_doctor.py": "recon_tool.mcp_client.client_doctor",
    "formatter_classify.py": "recon_tool.formatter.classify",
    "formatter_classify_tables.py": "recon_tool.formatter.classify_tables",
    "formatter_exposure.py": "recon_tool.formatter.exposure",
    "formatter_layout.py": "recon_tool.formatter.layout",
    "formatter_markdown.py": "recon_tool.formatter.markdown",
    "formatter_serialize.py": "recon_tool.formatter.serialize",
    "mcp_doctor.py": "recon_tool.mcp_client.doctor",
    "mcp_install.py": "recon_tool.mcp_client.install",
    "server_app.py": "recon_tool.server.app",
    "server_ephemeral.py": "recon_tool.server.ephemeral",
    "server_graph.py": "recon_tool.server.graph",
    "server_introspection.py": "recon_tool.server.introspection",
    "server_lookup.py": "recon_tool.server.lookup",
    "server_posture.py": "recon_tool.server.posture",
    "server_runtime.py": "recon_tool.server.runtime",
}

REQUIRED_PACKAGES = (
    "cli",
    "formatter",
    "mcp_client",
    "server",
)


def _is_interface_prefix(name: str) -> bool:
    return name.startswith(("cli_", "formatter_", "server_", "mcp_")) or name == "client_doctor.py"


def main() -> int:
    failures: list[str] = []

    for package in REQUIRED_PACKAGES:
        init_path = PKG / package / "__init__.py"
        if not init_path.exists():
            failures.append(f"missing package initializer: {init_path.relative_to(ROOT).as_posix()}")

    for path in sorted(PKG.glob("*.py")):
        name = path.name
        if not _is_interface_prefix(name):
            continue
        target = ALLOWED_SHIMS.get(name)
        if target is None:
            failures.append(f"unexpected top-level interface module: {path.relative_to(ROOT).as_posix()}")
            continue

        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if len(lines) > MAX_SHIM_LINES:
            failures.append(
                f"{path.relative_to(ROOT).as_posix()} has {len(lines)} lines; "
                f"compatibility shims must stay <= {MAX_SHIM_LINES}"
            )
        if "Compatibility shim" not in text:
            failures.append(f"{path.relative_to(ROOT).as_posix()} is missing compatibility-shim marker text")
        expected = f'importlib.import_module("{target}")'
        if expected not in text:
            failures.append(f"{path.relative_to(ROOT).as_posix()} must alias {target!r}")

    if failures:
        print("FAIL: interface package-locality guard violated:")
        print("\n".join(f"  {failure}" for failure in failures))
        return 1

    print(
        "OK: interface implementation lives under cli/, formatter/, "
        "server/, and mcp_client/; top-level compatibility shims are bounded."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
