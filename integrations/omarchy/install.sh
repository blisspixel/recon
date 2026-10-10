#!/usr/bin/env bash
# Install the Recon plugin for Omarchy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${HOME}/.config/omarchy/plugins/org.recon.omarchy"

echo "Installing Recon Omarchy integration..."

# Check that recon is available on PATH
if ! command -v recon >/dev/null 2>&1; then
    echo "Warning: 'recon' executable was not found on PATH." >&2
    echo "Install recon first with:" >&2
    echo "  uv tool install recon-tool" >&2
    echo "or" >&2
    echo "  pipx install recon-tool" >&2
fi

# Create target plugin directory
mkdir -p "${TARGET_DIR}"

# Copy files directly (no symlinks)
cp "${SCRIPT_DIR}/manifest.json" "${TARGET_DIR}/"
cp "${SCRIPT_DIR}/Widget.qml" "${TARGET_DIR}/"
cp "${SCRIPT_DIR}/ReconView.qml" "${TARGET_DIR}/"
cp "${SCRIPT_DIR}/README.md" "${TARGET_DIR}/"

echo "Recon plugin installed successfully to ${TARGET_DIR}."
if command -v omarchy-restart-shell >/dev/null 2>&1; then
    echo "Restarting Omarchy shell to load plugin..."
    omarchy-restart-shell || true
else
    echo "To load the plugin, restart your Omarchy shell."
fi
