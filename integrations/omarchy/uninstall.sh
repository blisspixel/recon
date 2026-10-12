#!/usr/bin/env bash
# Disable the owned Recon entry before removing its plugin files.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lifecycle.sh"

uninstall_plugin() {
    local target_dir="$1" reply
    setup_host || return 1
    read_plugin_state || return 1
    if [[ -L ${target_dir} ]]; then
        echo "Refusing to remove a symlinked plugin directory." >&2
        return 1
    fi
    if jq -e '.entries | length > 0' <<<"${PLUGIN_STATE}" >/dev/null; then
        reply="$(host_call setPluginEnabled "${RECON_PLUGIN_ID}" false)" || return 1
        if [[ ${reply} != ok ]]; then
            echo "Omarchy did not disable Recon; files were preserved. Retry once the shell is ready." >&2
            return 1
        fi
        read_plugin_state || return 1
        if ! jq -e '.entries | length == 0' <<<"${PLUGIN_STATE}" >/dev/null; then
            echo "Recon is still enabled; files were preserved." >&2
            return 1
        fi
    fi
    rm -rf -- "${target_dir}"
    host_call rescanPlugins >/dev/null || return 1
    wait_for_plugin_absent || return 1
    echo "Recon panel disabled and removed. No shell restart was performed."
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    uninstall_plugin "${HOME}/.config/omarchy/plugins/org.recon.omarchy"
fi
