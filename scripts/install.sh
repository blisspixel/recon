#!/usr/bin/env bash
# One-line installer / updater for recon (macOS / Linux).
#
# Install or update (same command — re-run any time to upgrade to the latest):
#   curl -fsSL https://raw.githubusercontent.com/blisspixel/recon/main/scripts/install.sh | bash
#
# Uninstall:
#   uv tool uninstall recon-tool   # or: pipx uninstall recon-tool
#
# Prefers uv (fast, manages its own Python); falls back to pipx; bootstraps pipx
# with system python3 if neither is present. Idempotent: a second run upgrades.

set -euo pipefail

PACKAGE="recon-tool"
CLI="recon"

have() { command -v "$1" >/dev/null 2>&1; }

install_or_upgrade_uv() {
    # `upgrade` succeeds only if already installed; on first run it fails and we
    # fall through to install. Either path lands on the latest published version.
    echo "==> Installing/updating $PACKAGE with uv ..."
    uv tool upgrade "$PACKAGE" 2>/dev/null || uv tool install "$PACKAGE"
}

install_or_upgrade_pipx() {
    echo "==> Installing/updating $PACKAGE with pipx ..."
    pipx upgrade "$PACKAGE" 2>/dev/null || pipx install "$PACKAGE"
}

if have uv; then
    install_or_upgrade_uv
elif have pipx; then
    install_or_upgrade_pipx
elif have python3; then
    # No isolated-tool installer yet. Bootstrap pipx with the system Python.
    PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
    if [ "$(printf '%s\n' "3.11" "$PYVER" | sort -V | head -1)" != "3.11" ]; then
        echo "Error: Python 3.11+ is required (found $PYVER), or install uv first:" >&2
        echo "  curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
        exit 1
    fi
    echo "==> pipx/uv not found; bootstrapping pipx with python3 ..."
    python3 -m pip install --user --quiet pipx
    python3 -m pipx ensurepath
    export PATH="$HOME/.local/bin:$PATH"
    install_or_upgrade_pipx
else
    echo "Error: need uv, pipx, or python3 (3.11+). Install uv (recommended):" >&2
    echo "  curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    echo "then re-run this installer." >&2
    exit 1
fi

INSTALLED_VERSION=$("$CLI" --version 2>/dev/null || echo "")

echo ""
echo "==> Done. ${INSTALLED_VERSION:-$PACKAGE installed}."
echo ""
echo "Next steps:"
echo "  1. Open a new terminal (so PATH updates take effect)"
echo "  2. Run: $CLI doctor"
echo ""
echo "Quick start:"
echo "  $CLI example.com"
echo "  $CLI example.com --json"
echo ""
echo "Optional: enable tab-completion with  $CLI --install-completion"
echo ""
echo "Update later: re-run this same command."
echo "Uninstall:    uv tool uninstall $PACKAGE   (or: pipx uninstall $PACKAGE)"
echo ""
