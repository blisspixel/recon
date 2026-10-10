#!/usr/bin/env bash
# Uninstall the Recon plugin from Omarchy.
set -euo pipefail

TARGET_DIR="${HOME}/.config/omarchy/plugins/org.recon.omarchy"

if [ -d "${TARGET_DIR}" ]; then
    echo "Removing Recon plugin from ${TARGET_DIR}..."
    rm -rf "${TARGET_DIR}"
    echo "Recon plugin removed."
    if command -v omarchy-restart-shell >/dev/null 2>&1; then
        echo "Restarting Omarchy shell to update plugins..."
        omarchy-restart-shell || true
    else
        echo "To apply changes, restart your Omarchy shell."
    fi
else
    echo "Recon plugin is not installed at ${TARGET_DIR}."
fi
