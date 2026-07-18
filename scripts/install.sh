#!/usr/bin/env bash
# Installer / updater for recon (macOS / Linux).
#
# Review this file from a release-tag checkout, then install or update with:
#   bash scripts/install.sh
#
# Uninstall:
#   uv tool uninstall recon-tool   # or: pipx uninstall recon-tool
#
# Prefers uv (fast, manages its own Python); falls back to pipx. Idempotent: a
# second run upgrades.

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

fail_missing_tool() {
    echo "Error: install uv or pipx first, then re-run this installer." >&2
    echo "Recommended:" >&2
    echo "  https://docs.astral.sh/uv/getting-started/installation/" >&2
    echo "Alternative:" >&2
    echo "  https://pipx.pypa.io/stable/installation/" >&2
    exit 1
}

if ! have uv && ! have pipx; then
    fail_missing_tool
fi

if have uv; then
    install_or_upgrade_uv
elif have pipx; then
    install_or_upgrade_pipx
else
    fail_missing_tool
fi

INSTALLED_VERSION=$("$CLI" --version 2>/dev/null || echo "")

echo ""
echo "==> Done. ${INSTALLED_VERSION:-$PACKAGE installed}."
echo ""
echo "Next steps:"
echo "  1. Open a new terminal (so PATH updates take effect)"
echo "  2. Offline install check: $CLI --version"
echo "  3. Optional online source connectivity: $CLI doctor"
echo ""
echo "Quick start:"
echo "  DNS infrastructure may observe lookup queries; the only default"
echo "  target-owned HTTP request is the MTA-STS policy fetch. Google CSE"
echo "  and BIMI direct probes run only with --direct-probes."
echo "  $CLI example.com"
echo "  $CLI example.com --json"
echo ""
echo "Optional: enable tab-completion with  $CLI --install-completion"
echo ""
echo "Update later: re-run this same command."
echo "Uninstall:    uv tool uninstall $PACKAGE   (or: pipx uninstall $PACKAGE)"
echo ""
