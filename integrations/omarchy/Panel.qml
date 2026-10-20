import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import "Settings.js" as Settings
import "ThemePalette.js" as ThemePalette

// The host injects these facades before delivering open(payloadJson).
Item {
    id: root
    property string omarchyPath: ""
    property var shell: null
    property var manifest: null
    property bool opened: false
    property bool settingsReady: false
    property bool showSettings: false
    property var settingsEntry: ({})
    property var admitted: null
    property string readPurpose: "load"
    property var pendingPatch: ({})
    property var expectedPatch: ({})
    property bool readTimedOut: false
    property string configText: ""
    property bool configReading: false
    property bool configStarted: false
    property string payloadError: ""
    property var payload: ({})
    readonly property bool configBusy: root.configReading
    property alias view: reconView
    property alias processRunner: runner
    property alias settingsEditor: settingsForm
    // Status keys parsed from the active theme's colors.toml (see ThemePalette.js).
    property var themeKeys: ({})
    readonly property string themePath: typeof Color.currentThemePath === "string" && Color.currentThemePath.length > 0
        ? Color.currentThemePath : Quickshell.env("HOME") + "/.local/state/omarchy/current/theme"
    readonly property bool lightTheme: ThemePalette.isLight(root.themeKeys, Color.background)
    readonly property var statusColors: ThemePalette.statusRoles(root.themeKeys, root.lightTheme, Color.urgent)
    readonly property var nativeColors: ({
        background: Color.popups.background, surface: Color.popups.background,
        foreground: Color.foreground, secondary: Color.foreground, muted: Color.muted,
        border: Qt.rgba(Color.foreground.r, Color.foreground.g, Color.foreground.b, 0.15),
        accent: Color.accent, onAccent: Color.background,
        success: root.statusColors.success, warning: root.statusColors.warning, error: root.statusColors.error,
        info: root.statusColors.info,
        successFill: root.statusColors.successFill,
        warningFill: root.statusColors.warningFill,
        errorFill: root.statusColors.errorFill,
        infoFill: root.statusColors.infoFill
    })

    function open(payloadJson) {
        root.payload = ({});
        root.payloadError = "";
        try {
            var value = JSON.parse(payloadJson || "{}");
            if (!Settings.isObject(value) || Object.keys(value).some(function(key) { return key !== "domain" && key !== "mode"; }))
                throw new Error("Expected only domain and mode in the summon payload.");
            if (Settings.owns(value, "mode") && value.mode !== "lookup" && value.mode !== "delta")
                throw new Error("Payload mode must be lookup or delta.");
            if (Settings.owns(value, "domain")) {
                var check = reconView.validateDomainInput(value.domain);
                if (!check.valid)
                    throw new Error(check.error);
                value.domain = check.domain;
            }
            root.payload = value;
        } catch (error) {
            root.payloadError = "Invalid summon payload: " + error.message;
        }
        root.opened = true;
        themeColorsFile.reload();
        root.refreshSettings("load", ({}));
    }

    function close() {
        runner.stop("cancelled");
        root.opened = false;
    }

    function dismiss() {
        root.close();
        if (root.shell)
            root.shell.hide(Settings.pluginId);
    }

    function configError(message) {
        root.settingsReady = false;
        reconView.errorMessage = message;
        settingsForm.errorMessage = message;
    }

    function refreshSettings(purpose, patch) {
        if (root.configBusy) {
            root.configError("Omarchy settings read is still in progress. Try again.");
            return;
        }
        root.settingsReady = false;
        root.readPurpose = purpose;
        root.pendingPatch = patch;
        root.readTimedOut = false;
        root.configText = "";
        root.configReading = true;
        root.configStarted = false;
        configProcess.command = [root.omarchyPath + "/bin/omarchy-shell", "shell", "listShellConfig"];
        configProcess.running = true;
        configTimeout.restart();
    }

    function receivedSettings(exitCode) {
        configTimeout.stop();
        root.configReading = false;
        if (!root.opened || root.readTimedOut) {
            root.configText = "";
            return;
        }
        try {
            if (exitCode !== 0)
                throw new Error("Could not read Omarchy settings. Check that the shell is running and rerun install.sh.");
            var config = JSON.parse(root.configText);
            root.configText = "";
            var entry = Settings.entryFromConfig(config);
            config = null;
            // Keep only the own entry; never log the host configuration.
            root.settingsEntry = entry;
            var patch = root.pendingPatch;
            if (root.readPurpose === "load" && !Settings.owns(entry, "reconCommand") && root.manifest && Settings.owns(root.manifest, "defaultLauncher"))
                patch = {reconCommand: root.manifest.defaultLauncher};
            if (Object.keys(patch).length > 0) {
                var merged = Settings.merge(entry, patch);
                if (!root.shell || typeof root.shell.updateEntryInline !== "function")
                    throw new Error("Omarchy did not supply the plugin settings facade.");
                root.shell.updateEntryInline(Settings.pluginId, merged);
                root.expectedPatch = patch;
                Qt.callLater(function() { if (root.opened) root.refreshSettings("verify", ({})); });
                return;
            }
            if (root.readPurpose === "verify" && Object.keys(root.expectedPatch).some(function(key) { return JSON.stringify(entry[key]) !== JSON.stringify(root.expectedPatch[key]); }))
                throw new Error("Omarchy did not accept the settings change. Reopen Settings to retry.");
            root.expectedPatch = ({});
            root.admitted = Settings.validate(entry);
            root.settingsReady = true;
            if (!runner.busy) {
                reconView.prefill(root.payload.domain, root.payload.mode || root.admitted.defaultMode);
                root.payload = ({});
            }
            reconView.errorMessage = root.payloadError;
            settingsForm.edit(entry);
        } catch (error) {
            root.configText = "";
            root.configError(error.message);
            settingsForm.edit(root.settingsEntry);
            settingsForm.errorMessage = error.message;
        }
    }

    function run(domain, delta) {
        if (!root.settingsReady || !root.admitted || runner.busy)
            return;
        var check = reconView.validateDomainInput(domain);
        if (!check.valid) {
            reconView.errorMessage = check.error;
            return;
        }
        runner.start(root.admitted.reconCommand, check.domain, delta, root.admitted.timeoutSec);
    }

    ReconProcess {
        id: runner
        onStateChanged: {
            reconView.errorMessage = runner.errorMessage;
            if (state === "running") {
                reconView.lookupResult = null;
                reconView.deltaResult = null;
                reconView.activeDomain = domain;
                reconView.statusMessage = "Querying public metadata for " + domain + "...";
            } else if (state === "succeeded") {
                if (delta) {
                    reconView.deltaResult = result;
                    reconView.statusMessage = reconView.deltaCompletionMessage(result);
                } else {
                    reconView.lookupResult = result;
                    reconView.statusMessage = "Public metadata observation complete (" + result.services.length + " services observed).";
                }
            } else if (state === "no-baseline") {
                reconView.statusMessage = "No cached snapshot. Choose Record baseline to run an initial lookup.";
            } else {
                reconView.statusMessage = state === "cancelled" ? "Lookup cancelled." : "";
            }
        }
    }

    Process {
        id: configProcess
        stdout: SplitParser { onRead: function(data) { root.configText += data + "\n"; } }
        // Do not surface full IPC output or host configuration in diagnostics.
        stderr: SplitParser { onRead: function(data) { } }
        onStarted: root.configStarted = true
        onRunningChanged: if (!running && root.configReading && !root.configStarted) root.receivedSettings(-1)
        onExited: function(exitCode) { root.receivedSettings(exitCode); }
    }
    Timer {
        id: configTimeout
        interval: 5000
        onTriggered: {
            root.readTimedOut = true;
            configProcess.signal(9);
            root.configError("Omarchy settings read timed out. Reopen the panel to retry.");
        }
    }

    // The theme's colors file is read at open and again whenever the theme
    // changes while the panel is open. Omarchy replaces the whole theme
    // directory on a switch, so a watch on colors.toml itself would not
    // survive; the host's live palette roles and the theme.name file next to
    // that directory are the change signals. No shell is run for this.
    FileView {
        id: themeColorsFile
        path: root.themePath + "/colors.toml"
        watchChanges: false
        printErrors: false
        onLoaded: root.themeKeys = ThemePalette.parse(themeColorsFile.text())
        onLoadFailed: root.themeKeys = ({})
    }
    FileView {
        id: themeNameFile
        path: root.themePath + ".name"
        preload: false
        watchChanges: root.opened
        printErrors: false
        onFileChanged: themeReload.restart()
    }
    Connections {
        target: Color
        enabled: root.opened
        function onBackgroundChanged() { themeReload.restart(); }
        function onForegroundChanged() { themeReload.restart(); }
        function onAccentChanged() { themeReload.restart(); }
        function onUrgentChanged() { themeReload.restart(); }
        function onMutedChanged() { themeReload.restart(); }
    }
    Timer {
        id: themeReload
        // The host assigns its palette roles one at a time; read once after.
        interval: 50
        onTriggered: themeColorsFile.reload()
    }

    FloatingWindow {
        id: window
        visible: root.opened
        title: "Recon"
        implicitWidth: 720
        implicitHeight: 680
        color: root.nativeColors.background
        onVisibleChanged: if (!visible && root.opened) root.dismiss()

        ReconView {
            id: reconView
            anchors.fill: parent
            visible: !root.showSettings
            colors: root.nativeColors
            lightTheme: root.lightTheme
            fontFamily: Style.font.family
            isRunning: runner.busy
            canRun: root.settingsReady
            rawJson: runner.rawJson
            noBaseline: runner.state === "no-baseline"
            onRequestLookup: function(domain, delta) { root.run(domain, delta); }
            onRequestCancel: runner.stop("cancelled")
            onRequestClose: root.dismiss()
            onRequestSettings: {
                settingsForm.edit(root.settingsEntry);
                root.showSettings = true;
            }
            onRequestTerminal: function(domain) {
                if (root.settingsReady && !runner.busy)
                    Quickshell.execDetached([root.omarchyPath + "/bin/omarchy-launch-terminal", "--hold", root.admitted.reconCommand, domain, "--explain"]);
            }
        }

        Pane {
            anchors.fill: parent
            visible: root.showSettings
            padding: 20
            font.family: Style.font.family
            palette.window: root.nativeColors.background
            palette.windowText: root.nativeColors.foreground
            palette.base: root.nativeColors.surface
            palette.text: root.nativeColors.foreground
            palette.button: root.nativeColors.surface
            palette.buttonText: root.nativeColors.foreground
            palette.highlight: root.nativeColors.accent
            palette.highlightedText: root.nativeColors.onAccent
            background: Rectangle { color: root.nativeColors.background }
            ReconSettings {
                id: settingsForm
                anchors.fill: parent
                busy: root.configBusy
                onSaveRequested: function(patch) { root.refreshSettings("save", patch); }
                onDismissRequested: root.showSettings = false
            }
        }
    }

    Component.onDestruction: if (configProcess.running) configProcess.signal(9)
}
