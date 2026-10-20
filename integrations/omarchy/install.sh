#!/usr/bin/env bash
# Install and enable the on-demand Recon panel without restarting the shell.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lifecycle.sh"

install_plugin() {
    local target_dir="$1" launcher before_bar reply
    setup_host || return 1
    read_plugin_state || return 1
    if jq -e 'any(.entries[]; .location == "bar")' <<<"${PLUGIN_STATE}" >/dev/null; then
        echo "Recon still has a legacy bar placement. Existing files and settings were preserved." >&2
        echo "Export ONLY the Recon entry first; disabling deletes its settings. See README.md: Legacy bar migration." >&2
        return 1
    fi
    before_bar="$(jq -c '.bar' <<<"${PLUGIN_STATE}")"
    launcher="$(type -P recon)" || {
        echo "Install recon-tool with uv tool or pipx before installing this panel." >&2
        return 1
    }
    # Keep lexical shim identity: do not dereference the executable's symlink.
    [[ ${launcher} = /* ]] || launcher="${PWD}/${launcher}"
    if [[ ! -f ${launcher} || ! -x ${launcher} || -L ${target_dir} ]]; then
        echo "Recon requires an executable launcher and an owned plugin directory, not a directory symlink." >&2
        return 1
    fi
    mkdir -p -- "${target_dir}"
    cp -- "${SCRIPT_DIR}"/{Panel.qml,ReconView.qml,ReconSettings.qml,ReconProcess.qml,Settings.js,ThemePalette.js,README.md} "${target_dir}/"
    jq --arg launcher "${launcher}" '. + {defaultLauncher: $launcher}' "${SCRIPT_DIR}/manifest.json" >"${target_dir}/manifest.json"
    rm -f -- "${target_dir}/Widget.qml"
    host_call rescanPlugins >/dev/null || return 1
    wait_for_plugin || return 1
    reply="$(host_call enablePlugin "${RECON_PLUGIN_ID}" '{}')" || return 1
    if [[ ${reply} != ok ]]; then
        echo "Recon files were copied but Omarchy did not enable the panel: ${reply}. Rerun install.sh." >&2
        return 1
    fi
    read_plugin_state || return 1
    if ! jq -e '.entries | length == 1 and .[0].location == "plugin"' <<<"${PLUGIN_STATE}" >/dev/null || [[ $(jq -c '.bar' <<<"${PLUGIN_STATE}") != "${before_bar}" ]]; then
        echo "Could not verify the enabled panel and unchanged bar. Inspect Omarchy settings before retrying." >&2
        return 1
    fi
    echo "Recon panel enabled. The bar is unchanged; no shell restart was performed."
    echo "Open with: omarchy-shell shell toggle org.recon.omarchy '{}'"
    echo "See README.md for the opt-in keybinding and menu entry."
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    install_plugin "${HOME}/.config/omarchy/plugins/org.recon.omarchy"
fi
