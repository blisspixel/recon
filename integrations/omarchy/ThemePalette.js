.pragma library

// Status roles for the panel, matching the CLI roles: success is the active
// theme's green, warning its yellow and error its red. The accent stays for
// focus and selection. The Omarchy host Color singleton exposes only
// foreground, background, accent, urgent and muted, so the three status
// colors come from the theme's own colors.toml. Only the keys below are read;
// everything else in the file is ignored.

var wantedKeys = ["mode", "red", "yellow", "green", "color1", "color2", "color3"];

// Fixed light and dark sets for standalone previews and for themes whose
// colors file is missing, unreadable or lacks a status color.
var fallback = {
    dark: {
        background: "#181825", surface: "#1e1e2e", foreground: "#cdd6f4",
        secondary: "#a6adc8", muted: "#6c7086", border: "#313244",
        accent: "#89b4fa", onAccent: "#11111b", success: "#a6e3a1",
        warning: "#f9e2af", error: "#f38ba8", successFill: "#1e3a2f",
        warningFill: "#3d3525", errorFill: "#3e1f29"
    },
    light: {
        background: "#f7f7f8", surface: "#ffffff", foreground: "#1f2328",
        secondary: "#4b5058", muted: "#6e7781", border: "#d0d4da",
        accent: "#1f5fbf", onAccent: "#ffffff", success: "#1a7f37",
        warning: "#8a5d00", error: "#c4232f", successFill: "#e3f1e6",
        warningFill: "#f4ecdc", errorFill: "#f8e0e2"
    }
};

function hex(value) {
    var text = value === null || value === undefined ? "" : String(value);
    var match = text.match(/^#(?:[0-9A-Fa-f]{2})?([0-9A-Fa-f]{6})$/);
    return match ? "#" + match[1].toLowerCase() : "";
}

// Parse only the wanted keys from colors.toml text. Values that are not a
// six-digit hex color (or light/dark for mode) are dropped, never guessed.
function parse(raw) {
    var keys = {};
    var lines = String(raw || "").split("\n");
    for (var i = 0; i < lines.length; i++) {
        var match = lines[i].match(/^\s*([A-Za-z0-9_-]+)\s*=\s*["']?([^"'\s#]+|#[0-9A-Fa-f]{6})["']?\s*(?:#.*)?$/);
        if (!match || wantedKeys.indexOf(match[1]) === -1)
            continue;
        if (match[1] === "mode") {
            var mode = match[2].toLowerCase();
            if (mode === "light" || mode === "dark")
                keys.mode = mode;
        } else if (hex(match[2])) {
            keys[match[1]] = hex(match[2]);
        }
    }
    return keys;
}

function luminance(value) {
    var r, g, b;
    var text = hex(value);
    if (text) {
        r = parseInt(text.substr(1, 2), 16) / 255;
        g = parseInt(text.substr(3, 2), 16) / 255;
        b = parseInt(text.substr(5, 2), 16) / 255;
    } else if (value && typeof value.r === "number") {
        r = value.r;
        g = value.g;
        b = value.b;
    } else {
        return 0;
    }
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

// The theme's declared mode wins; otherwise judge the host background.
function isLight(keys, background) {
    if (keys && keys.mode === "light")
        return true;
    if (keys && keys.mode === "dark")
        return false;
    return luminance(background) > 0.5;
}

// Status fills keep the 12 percent tint the panel always used, as #AARRGGBB.
function fill(color) {
    var text = hex(color);
    return text ? "#1f" + text.substr(1) : "transparent";
}

function statusRoles(keys, light, hostUrgent) {
    var base = light ? fallback.light : fallback.dark;
    keys = keys || {};
    var roles = {
        success: keys.green || keys.color2 || "",
        warning: keys.yellow || keys.color3 || "",
        error: keys.red || keys.color1 || hex(hostUrgent) || ""
    };
    var source = "theme";
    // A theme missing a role, or one that gives two roles the same color,
    // uses the fallback set so the three meanings stay distinct. Error keeps
    // the host's own urgent role when it differs from both fallback colors.
    if (!roles.success || !roles.warning || !roles.error
            || roles.success === roles.warning || roles.warning === roles.error || roles.success === roles.error) {
        var urgent = hex(hostUrgent);
        roles = {
            success: base.success,
            warning: base.warning,
            error: urgent && urgent !== base.success && urgent !== base.warning ? urgent : base.error
        };
        source = "fallback";
    }
    return {
        source: source,
        success: roles.success,
        warning: roles.warning,
        error: roles.error,
        successFill: fill(roles.success),
        warningFill: fill(roles.warning),
        errorFill: fill(roles.error)
    };
}
