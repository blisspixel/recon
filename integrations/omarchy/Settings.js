.pragma library

var pluginId = "org.recon.omarchy";

function owns(object, key) {
    return Object.prototype.hasOwnProperty.call(object, key);
}

function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function entryFromConfig(config) {
    if (!isObject(config) || config.version !== 1 || !Array.isArray(config.plugins))
        throw new Error("Omarchy did not return a valid version 1 plugin configuration.");
    var entries = config.plugins.filter(function(entry) {
        return isObject(entry) && entry.id === pluginId;
    });
    var layout = config.bar && config.bar.layout;
    if (layout && ["left", "center", "right"].some(function(section) {
        return Array.isArray(layout[section]) && layout[section].some(function(entry) {
            return entry === pluginId || (isObject(entry) && entry.id === pluginId);
        });
    }))
        throw new Error("Recon has a legacy bar placement. See the plugin migration instructions.");
    if (entries.length !== 1)
        throw new Error("Recon must have exactly one enabled Omarchy plugin entry. Rerun install.sh.");
    return JSON.parse(JSON.stringify(entries[0]));
}

function validate(entry) {
    var command = entry.reconCommand;
    var timeout = owns(entry, "timeoutSec") ? entry.timeoutSec : 30;
    var mode = owns(entry, "defaultMode") ? entry.defaultMode : "lookup";
    if (typeof command !== "string" || command.charAt(0) !== "/" || /[\x00-\x1f\x7f]/.test(command))
        throw new Error("Recon launcher must be an absolute executable path. Repair it in Settings.");
    if (typeof timeout !== "number" || !isFinite(timeout) || Math.floor(timeout) !== timeout || timeout < 10 || timeout > 120)
        throw new Error("Timeout must be an integer from 10 to 120 seconds.");
    if (mode !== "lookup" && mode !== "delta")
        throw new Error("Default mode must be lookup or delta.");
    return {reconCommand: command, timeoutSec: timeout, defaultMode: mode};
}

function merge(entry, patch) {
    var merged = JSON.parse(JSON.stringify(entry));
    Object.keys(patch).forEach(function(key) {
        if (["reconCommand", "timeoutSec", "defaultMode"].indexOf(key) === -1)
            throw new Error("Unsupported Recon setting.");
        merged[key] = patch[key];
    });
    validate(merged);
    return merged;
}
