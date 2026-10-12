#!/usr/bin/env bash
# Shared host transport and ownership checks for the explicit setup commands.

RECON_PLUGIN_ID="org.recon.omarchy"

host_call() {
    "${TIMEOUT_COMMAND}" --kill-after=1s 1s "${OMARCHY_SHELL}" shell "$@" || {
        echo "Omarchy IPC $1 failed or timed out. Check the running shell before retrying this script." >&2
        return 1
    }
}

read_plugin_state() {
    local config
    config="$(host_call listShellConfig)" || {
        echo "Omarchy shell is unavailable. Start it, then rerun this script; no shell restart is performed." >&2
        return 1
    }
    # Project only this plugin's entries. Never print or save full host config.
    PLUGIN_STATE="$(jq -sce --arg id "${RECON_PLUGIN_ID}" '
        def valid_id: type == "string" and length > 0;
        def valid_entry: type == "object" and (.id | valid_id);
        if length != 1 then error("invalid host configuration") else .[0] end
        | if type == "object" and .version == 1
            and (.plugins | type == "array" and all(.[]; valid_entry))
            and (.bar | type == "object") and (.bar.layout | type == "object")
            and (.bar.layout | [.left, .center, .right] | all(.[];
                type == "array" and all(.[]; valid_id or valid_entry)))
          then . else error("invalid host configuration") end
        | {bar: .bar, entries: ([.plugins[] | select(.id == $id) | {location: "plugin", settings: .}]
          + [(.bar.layout.left + .bar.layout.center + .bar.layout.right)[]
            | select((if type == "string" then . else .id end) == $id) | {location: "bar", settings: .}])}
    ' <<<"${config}")" || {
        echo "Omarchy returned an invalid configuration; setup state is unverified. Inspect its configuration before retrying." >&2
        return 1
    }
    local count
    count="$(jq '.entries | length' <<<"${PLUGIN_STATE}")"
    if (( count > 1 )); then
        echo "Recon has duplicate Omarchy entries. Resolve those entries before setup; existing files and settings are preserved." >&2
        return 1
    fi
}

wait_for_plugin() {
    local attempt plugins
    for attempt in {1..20}; do
        plugins="$(host_call listPlugins)" || return 1
        if jq -e --arg id "${RECON_PLUGIN_ID}" 'type == "array" and any(.[]; .id == $id and .kinds == ["panel"])' <<<"${plugins}" >/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    echo "Omarchy did not discover Recon after rescanning. Rerun install.sh once the shell is ready." >&2
    return 1
}

wait_for_plugin_absent() {
    local attempt plugins present
    for attempt in {1..20}; do
        plugins="$(host_call listPlugins)" || {
            echo "Omarchy could not read plugin inventory after removal. Rerun uninstall.sh once the shell is ready." >&2
            return 1
        }
        present="$(jq -sc --arg id "${RECON_PLUGIN_ID}" '
            if length != 1 then error("invalid plugin inventory") else .[0] end
            | if type == "array" and all(.[]; type == "object" and (.id | type) == "string")
            then any(.[]; .id == $id)
            else error("invalid plugin inventory") end
        ' <<<"${plugins}")" || present="invalid"
        case ${present} in
            false) return 0 ;;
            true) sleep 0.1 ;;
            *)
                echo "Omarchy returned invalid plugin inventory; removal is unverified. Rerun uninstall.sh once the shell is ready." >&2
                return 1
                ;;
        esac
    done
    echo "Omarchy still lists Recon after rescanning; removal is unverified. Rerun uninstall.sh once the shell is ready." >&2
    return 1
}

setup_host() {
    command -v jq >/dev/null 2>&1 || {
        echo "Omarchy's jq utility is required for plugin setup." >&2
        return 1
    }
    TIMEOUT_COMMAND="$(type -P timeout)" || {
        echo "Omarchy's coreutils timeout command is required for bounded setup verification; no changes were made." >&2
        return 1
    }
    OMARCHY_SHELL="$(type -P omarchy-shell)" || {
        echo "omarchy-shell was not found. Run this script from an Omarchy session." >&2
        return 1
    }
}
