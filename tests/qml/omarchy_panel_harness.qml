import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import "Recon" as Recon

ShellRoot {
    id: test
    property string fixture: Quickshell.env("RECON_QML_ROOT")
    property string launcher: fixture + "/bin/recon"
    property var config: ({version: 1, plugins: [{id: "org.recon.omarchy", unrelated: {keep: true}}]})
    property var invocations: []
    property var terminalArgs: []
    property int writes: 0
    property bool malformedConfig: false
    property bool stalledConfig: false
    property bool refuseWrites: false
    property int hides: 0
    property var cases: []
    property var passed: []
    property int current: 0
    property double deadline: 0
    property int before: 0
    property bool imageReady: false

    function assertThat(value, message) {
        if (!value)
            throw new Error(message);
    }
    function same(actual, expected, message) {
        assertThat(JSON.stringify(actual) === JSON.stringify(expected), message);
    }
    function child(item, name) {
        if (item.objectName === name)
            return item;
        for (var i = 0; i < item.children.length; i++) {
            var found = child(item.children[i], name);
            if (found)
                return found;
        }
        return null;
    }
    function add(name, start, finish) {
        cases.push({name: name, start: start, finish: finish, started: false});
    }
    function validEntry() {
        return {id: "org.recon.omarchy", reconCommand: launcher, timeoutSec: 10, defaultMode: "lookup"};
    }
    function openValid() {
        config = {version: 1, plugins: [validEntry()]};
        panel.open("{}");
    }
    function resultReady(state) {
        return panel.processRunner.state === state && !panel.processRunner.busy;
    }
    function inspect(domain, delta) {
        panel.view.prefill(domain, delta ? "delta" : "lookup");
        panel.view.runInspection();
    }
    function assertLookupHeader(domain) {
        var coordinate = child(panel.view, "queriedDomain");
        var display = child(panel.view, "displayName");
        assertThat(coordinate && coordinate.visible && coordinate.width > 0 && coordinate.height > 0 && coordinate.text === domain, "Visible queried domain missing");
        assertThat(display && display.visible && display.width > 0 && display.height > 0 && display.text === "(Synthetic Example)", "Visible display name missing");
    }
    function capture(name) {
        imageReady = false;
        panel.view.grabToImage(function(image) {
            assertThat(image.saveToFile(fixture + "/" + name), "Image save failed");
            imageReady = true;
        });
    }

    SocketServer {
        active: true
        path: Quickshell.env("RECON_QML_SOCKET")
        handler: Socket {
            id: connection
            parser: SplitParser {
                onRead: function(data) {
                    var request = JSON.parse(data);
                    if (request.kind === "config") {
                        if (!test.stalledConfig)
                            connection.write((test.malformedConfig ? "broken" : JSON.stringify(test.config)) + "\n");
                    } else if (request.kind === "cli") {
                        test.invocations = test.invocations.concat([request.args]);
                        connection.write("ok\n");
                    } else if (request.kind === "terminal") {
                        test.terminalArgs = request.args;
                        connection.write("ok\n");
                    }
                    connection.flush();
                }
            }
        }
    }

    Recon.Panel {
        id: panel
        omarchyPath: test.fixture
        manifest: ({defaultLauncher: test.launcher})
        shell: ({
            updateEntryInline: function(id, entry) {
                test.assertThat(id === "org.recon.omarchy", "Facade target escaped own id");
                if (test.refuseWrites)
                    return false;
                var copy = JSON.parse(JSON.stringify(test.config));
                copy.plugins[0] = entry;
                test.config = copy;
                test.writes++;
                return true;
            },
            hide: function(id) {
                test.assertThat(id === "org.recon.omarchy", "Wrong panel hidden");
                test.hides++;
            }
        })
    }
    property TextEdit clipboard: TextEdit { textFormat: TextEdit.PlainText }
    // Synthetic theme files under the private state root; the panel reads them
    // through the fake host Color.currentThemePath, never a real user theme.
    property string themeDir: fixture + "/state/omarchy/current/theme"
    property string lightToml: ['mode = "light"', 'background = "#f3f3f3"', 'red = "#a01929"',
        'yellow = "#8a5d00"', 'green = "#1a7f37"', ''].join(String.fromCharCode(10))
    property string renamedToml: ['mode = "light"', 'background = "#f3f3f3"', 'red = "#a01929"',
        'yellow = "#8a5d00"', 'green = "#0b6e4f"', ''].join(String.fromCharCode(10))
    property bool lightApplied: false
    property bool captureStarted: false
    FileView {
        id: themeWriter
        path: test.themeDir + "/colors.toml"
        preload: false
        onSaved: {
            if (!test.lightApplied) {
                test.lightApplied = true;
                // The host switches its foundational roles after the files move.
                Color.background = "#f3f3f3";
                Color.foreground = "#202020";
                Color.accent = "#174ba0";
                Color.muted = "#575757";
                Color.urgent = "#a01929";
            } else {
                themeNameWriter.setText("renamed" + String.fromCharCode(10));
            }
        }
    }
    FileView {
        id: themeNameWriter
        path: test.themeDir + ".name"
        preload: false
    }
    function distinctStatus() {
        var c = panel.nativeColors;
        return c.success !== c.warning && c.warning !== c.error && c.success !== c.error;
    }

    Component.onCompleted: {
        add("absent-only seed", function() { panel.open("{}"); }, function() {
            if (!panel.settingsReady) return false;
            same(config.plugins[0], {id: "org.recon.omarchy", unrelated: {keep: true}, reconCommand: launcher}, "Seed dropped own settings");
            assertThat(writes === 1 && invocations.length === 0, "Seed dispatched or wrote twice");
            return true;
        });
        add("passive opening and payload", function() { panel.open('{"domain":"ALPHA.invalid","mode":"delta"}'); }, function() {
            if (!panel.settingsReady) return false;
            assertThat(panel.view.deltaMode && invocations.length === 0, "Opening dispatched a lookup");
            return true;
        });
        add("fresh settings merge", function() {
            panel.settingsEditor.edit(panel.settingsEntry);
            config.plugins[0].unrelated = {updatedBeforeRead: true};
            config.plugins[0].defaultMode = "delta";
            child(panel.settingsEditor, "timeoutSec").text = "12";
            panel.settingsEditor.save();
        }, function() {
            if (!panel.settingsReady) return false;
            assertThat(config.plugins[0].timeoutSec === 12 && config.plugins[0].defaultMode === "delta" && config.plugins[0].unrelated.updatedBeforeRead, "Save overwrote fresh unedited settings");
            return true;
        });
        add("unchanged settings", function() {
            before = writes;
            panel.settingsEditor.save();
        }, function() {
            if (panel.configBusy) return false;
            assertThat(panel.settingsReady && writes === before, "Unedited form wrote the entry");
            return true;
        });
        add("explicit invalid value", function() {
            config.plugins[0].reconCommand = null;
            before = writes;
            panel.open("{}");
        }, function() {
            if (panel.configBusy) return false;
            assertThat(!panel.settingsReady && writes === before && config.plugins[0].reconCommand === null, "Explicit invalid setting was replaced");
            return true;
        });
        add("settings repair", function() {
            panel.settingsEditor.edit(panel.settingsEntry);
            child(panel.settingsEditor, "reconCommand").text = launcher;
            panel.settingsEditor.save();
        }, function() { return panel.settingsReady; });
        add("explicit empty value", function() {
            config.plugins[0].reconCommand = "";
            before = writes;
            panel.open("{}");
        }, function() {
            if (panel.configBusy) return false;
            assertThat(!panel.settingsReady && writes === before && config.plugins[0].reconCommand === "", "Explicit empty setting was replaced");
            return true;
        });
        add("empty value repair", function() {
            child(panel.settingsEditor, "reconCommand").text = launcher;
            panel.settingsEditor.save();
        }, function() { return panel.settingsReady; });
        add("invalid form", function() {
            before = writes;
            child(panel.settingsEditor, "timeoutSec").text = "30.5";
            panel.settingsEditor.save();
        }, function() {
            assertThat(writes === before && panel.settingsEditor.errorMessage.length > 0, "Fractional timeout admitted");
            return true;
        });
        add("invalid bounds and mode", function() {
            ["9", "121", "invalid"].forEach(function(value) {
                panel.settingsEditor.edit(panel.settingsEntry);
                child(panel.settingsEditor, "timeoutSec").text = value;
                panel.settingsEditor.save();
                assertThat(panel.settingsEditor.errorMessage.length > 0 && writes === before, "Invalid timeout wrote settings");
            });
            panel.settingsEditor.edit(panel.settingsEntry);
            child(panel.settingsEditor, "defaultMode").currentIndex = -1;
            panel.settingsEditor.save();
            assertThat(panel.settingsEditor.errorMessage.length > 0 && writes === before, "Invalid mode wrote settings");
        }, function() { return true; });
        add("refused settings write", function() {
            refuseWrites = true;
            panel.settingsEditor.edit(panel.settingsEntry);
            child(panel.settingsEditor, "timeoutSec").text = "15";
            panel.settingsEditor.save();
        }, function() {
            if (panel.configBusy || panel.view.errorMessage.indexOf("did not accept") === -1) return false;
            assertThat(!panel.settingsReady && config.plugins[0].timeoutSec === 12, "Refused change admitted");
            refuseWrites = false;
            return true;
        });
        add("missing settings executable", function() {
            panel.omarchyPath = fixture + "/missing";
            panel.open("{}");
        }, function() {
            if (panel.configBusy) return false;
            assertThat(!panel.settingsReady && panel.view.errorMessage.indexOf("Could not read") === 0, "Missing settings executable admitted");
            panel.omarchyPath = fixture;
            return true;
        });
        add("settings timeout", function() {
            stalledConfig = true;
            panel.open("{}");
            deadline = Date.now() + 8000;
        }, function() {
            if (panel.configBusy) return false;
            assertThat(!panel.settingsReady && panel.view.errorMessage.indexOf("Omarchy settings read timed out") === 0 && panel.configText === "", "Settings timeout lost diagnosis or admitted dispatch");
            stalledConfig = false;
            return true;
        });
        add("malformed payload", function() { panel.open("{"); }, function() {
            if (!panel.settingsReady) return false;
            assertThat(panel.view.errorMessage.indexOf("Invalid summon payload") === 0 && invocations.length === 0, "Malformed payload ran or lost its error");
            return true;
        });
        add("malformed config", function() { malformedConfig = true; panel.open("{}"); }, function() {
            if (panel.configBusy) return false;
            assertThat(!panel.settingsReady && invocations.length === 0 && panel.configText === "", "Malformed config admitted or retained");
            return true;
        });
        add("duplicate config", function() {
            malformedConfig = false;
            config = {version: 1, plugins: [validEntry(), validEntry()]};
            panel.open("{}");
        }, function() {
            if (panel.configBusy) return false;
            assertThat(!panel.settingsReady && invocations.length === 0, "Duplicate own entries admitted");
            return true;
        });
        add("legacy string placement", function() {
            config = {version: 1, plugins: [validEntry()], bar: {layout: {left: ["org.recon.omarchy"], center: [], right: []}}};
            panel.open("{}");
        }, function() {
            if (panel.configBusy) return false;
            assertThat(!panel.settingsReady && panel.view.errorMessage.indexOf("legacy bar placement") >= 0 && invocations.length === 0, "Legacy string placement admitted");
            openValid();
            return true;
        });
        add("canonical lookup argv", function() { }, function() {
            if (!panel.settingsReady) return false;
            if (panel.processRunner.state === "idle") inspect("success.invalid", false);
            if (!resultReady("succeeded")) return false;
            same(invocations[0], ["success.invalid", "--json"], "Lookup argument boundaries changed");
            assertThat(panel.processRunner.result.queried_domain === "success.invalid", "Canonical lookup coordinate lost");
            same(panel.processRunner.rawJson, Quickshell.env("RECON_QML_EXPECTED_LOOKUP"), "Canonical formatter bytes changed");
            assertLookupHeader("success.invalid");
            return true;
        });
        add("copy and paste", function() {
            before = invocations.length;
            panel.view.copyJson();
            clipboard.paste();
        }, function() {
            same(clipboard.text, panel.processRunner.rawJson, "Raw JSON clipboard changed");
            panel.view.prefill("paste.invalid", "lookup");
            assertThat(invocations.length === before, "Copy or input dispatched a lookup");
            return true;
        });
        add("terminal argv", function() { panel.view.prefill("terminal.invalid", "lookup"); panel.view.openTerminal(); }, function() {
            if (!terminalArgs.length) return false;
            same(terminalArgs, ["--hold", launcher, "terminal.invalid", "--explain"], "Terminal transport was not fixed argv");
            assertThat(invocations.length === before, "Terminal helper test ran the collector");
            return true;
        });
        add("no baseline", function() { inspect("nobaseline.invalid", true); }, function() {
            if (!resultReady("no-baseline")) return false;
            before = invocations.length;
            same(invocations[before - 1], ["delta", "nobaseline.invalid", "--json"], "Delta arguments changed");
            return true;
        });
        add("explicit baseline", function() {
            assertThat(invocations.length === before, "Missing baseline automatically collected");
            child(panel.view, "recordBaseline").clicked();
        }, function() {
            if (!resultReady("succeeded")) return false;
            same(invocations[before], ["nobaseline.invalid", "--json"], "Explicit baseline did not run ordinary lookup");
            assertThat(invocations.length === before + 1, "Baseline chained an extra lookup");
            return true;
        });
        add("canonical delta", function() { inspect("canonicaldelta.invalid", true); }, function() {
            if (!resultReady("succeeded")) return false;
            assertThat(panel.processRunner.result.record_type === "delta" && panel.processRunner.result.domain === "canonicaldelta.invalid", "Canonical delta formatter rejected");
            return true;
        });
        add("invented lookup schema", function() { inspect("domainonly.invalid", false); }, function() {
            if (!resultReady("failed")) return false;
            assertThat(panel.processRunner.result === null && panel.processRunner.rawJson === "", "Invented domain-only schema admitted");
            return true;
        });
        add("invalid delta schema", function() { inspect("baddelta.invalid", true); }, function() {
            if (!resultReady("failed")) return false;
            assertThat(panel.processRunner.result === null && panel.processRunner.rawJson === "", "Invalid delta schema admitted");
            return true;
        });
        ["malformed", "empty", "nonzero"].forEach(function(kind) {
            add(kind + " result", function() { inspect((kind === "nonzero" ? "failure" : kind) + ".invalid", false); }, function() {
                if (!resultReady("failed")) return false;
                assertThat(panel.processRunner.result === null && panel.processRunner.rawJson === "", "Invalid output retained as result");
                return true;
            });
        });
        add("cancel start", function() { before = invocations.length; inspect("cancel.invalid", false); }, function() {
            if (invocations.length === before) return false;
            panel.processRunner.stop("cancelled");
            assertThat(!panel.processRunner.start(launcher, "wrong.invalid", false, 10), "New run admitted before exit");
            return true;
        });
        add("late cancelled exit", function() { }, function() {
            if (panel.processRunner.busy) return false;
            assertThat(panel.processRunner.state === "cancelled" && panel.processRunner.result === null, "Late exit overwrote cancellation");
            return true;
        });
        add("timeout start", function() { before = invocations.length; panel.processRunner.start(launcher, "timeout.invalid", false, 10); }, function() {
            if (invocations.length === before) return false;
            panel.processRunner.timeoutMs = 60;
            panel.processRunner.timeout.restart();
            return true;
        });
        add("late timeout exit", function() { }, function() {
            if (panel.processRunner.busy) return false;
            assertThat(panel.processRunner.state === "timed-out" && panel.processRunner.result === null, "Late exit overwrote timeout");
            assertThat(panel.view.errorMessage.indexOf("Lookup timed out") === 0, "Timeout diagnosis missing from panel");
            return true;
        });
        add("next run", function() { inspect("next.invalid", false); }, function() {
            if (!resultReady("succeeded")) return false;
            assertThat(panel.processRunner.result.queried_domain === "next.invalid", "Next run consumed stale output");
            return true;
        });
        add("missing executable", function() { panel.processRunner.start(launcher + "-missing", "missing.invalid", false, 0.1); }, function() {
            if (panel.processRunner.busy) return false;
            assertThat(panel.processRunner.state === "failed", "Unstartable launcher did not fail");
            return true;
        });
        add("forced termination start", function() { before = invocations.length; inspect("stubborn.invalid", false); }, function() {
            if (invocations.length === before) return false;
            panel.processRunner.stop("cancelled");
            return true;
        });
        add("forced termination exit", function() { }, function() {
            if (panel.processRunner.busy) return false;
            assertThat(panel.processRunner.state === "cancelled", "Forced termination lost cancellation");
            return true;
        });
        add("close running panel", function() { before = invocations.length; inspect("cancel.invalid", false); }, function() {
            if (invocations.length === before) return false;
            panel.dismiss();
            assertThat(!panel.opened && hides === 1, "Dismiss did not update host lifecycle");
            return true;
        });
        add("closed panel exit", function() { }, function() {
            if (panel.processRunner.busy) return false;
            assertThat(panel.processRunner.state === "cancelled", "Closed panel accepted late output");
            openValid();
            return true;
        });
        add("visual lookup", function() { before = invocations.length; }, function() {
            if (!panel.settingsReady) return false;
            if (invocations.length === before && !panel.processRunner.busy) {
                inspect("visual.invalid", false);
                return false;
            }
            return resultReady("succeeded");
        });
        add("dark render", function() { capture("dark.png"); }, function() {
            if (!imageReady) return false;
            same(panel.view.color.toString(), Color.background.toString(), "Dark palette detached");
            same([panel.nativeColors.success, panel.nativeColors.warning, panel.nativeColors.error],
                 ["#9ece6a", "#e0af68", "#f7768e"], "Dark theme status roles not read from colors.toml");
            assertThat(!panel.lightTheme && distinctStatus(), "Dark status roles collapsed");
            assertLookupHeader("visual.invalid");
            return true;
        });
        add("light render", function() {
            captureStarted = false;
            themeWriter.setText(lightToml);
        }, function() {
            if (panel.nativeColors.warning !== "#8a5d00") return false;
            if (!captureStarted) {
                captureStarted = true;
                capture("light.png");
                return false;
            }
            if (!imageReady) return false;
            same(panel.view.color.toString(), "#f3f3f3", "Light palette detached");
            assertThat(panel.lightTheme && panel.view.lightTheme && distinctStatus(), "Light status roles collapsed");
            same(panel.nativeColors.error, "#a01929", "Light error role detached");
            assertLookupHeader("visual.invalid");
            return true;
        });
        add("theme name recolor", function() { themeWriter.setText(renamedToml); }, function() {
            if (panel.nativeColors.success !== "#0b6e4f") return false;
            assertThat(distinctStatus(), "Renamed theme collapsed status roles");
            return true;
        });
        deadline = Date.now() + 3000;
        pump.start();
    }

    Timer {
        id: pump
        interval: 10
        repeat: true
        onTriggered: {
            try {
                if (test.current === test.cases.length) {
                    console.log("RECON_QML_PASSED " + JSON.stringify(test.passed));
                    stop();
                    panel.close();
                    Qt.quit();
                    return;
                }
                var item = test.cases[test.current];
                if (!item.started) {
                    item.started = true;
                    test.deadline = Date.now() + 3000;
                    item.start();
                }
                if (item.finish()) {
                    test.passed = test.passed.concat([item.name]);
                    test.current++;
                } else if (Date.now() > test.deadline) {
                    throw new Error("Timed out in " + item.name + ": " + panel.view.errorMessage);
                }
            } catch (error) {
                console.error("RECON_QML_FAILED " + error.message);
                stop();
                panel.close();
                Qt.quit();
            }
        }
    }
}
