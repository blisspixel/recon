import QtQuick
import Quickshell.Io

// Own one CLI invocation through actual exit, including termination callbacks.
QtObject {
    id: root

    property string state: "idle"
    property string domain: ""
    property bool delta: false
    property string errorMessage: ""
    property string rawJson: ""
    property var result: null
    property bool awaitingExit: false
    property bool started: false
    readonly property bool busy: awaitingExit || state === "running"
    property int timeoutMs: 30000

    function start(command, requestedDomain, isDelta, seconds) {
        if (root.busy)
            return false;
        root.domain = requestedDomain;
        root.delta = isDelta;
        root.errorMessage = "";
        root.rawJson = "";
        root.result = null;
        root.timeoutMs = seconds * 1000;
        root.state = "running";
        root.awaitingExit = true;
        root.started = false;
        process.command = isDelta ? [command, "delta", requestedDomain, "--json"] : [command, requestedDomain, "--json"];
        process.running = true;
        timeout.restart();
        return true;
    }

    function stop(reason) {
        if (root.state !== "running")
            return;
        root.errorMessage = reason === "timed-out" ? "Lookup timed out. The owned process is being stopped." : "";
        root.state = reason;
        timeout.stop();
        process.running = false;
        killTimer.restart();
    }

    function finish(exitCode) {
        timeout.stop();
        killTimer.stop();
        root.awaitingExit = false;
        // A terminal decision owns the status even if SIGTERM's exit is late.
        if (root.state !== "running")
            return;
        if (exitCode === 3 && root.delta) {
            root.state = "no-baseline";
            return;
        }
        if (exitCode !== 0) {
            root.errorMessage = errors.text.trim() || "Recon exited with status " + exitCode + ". Check the launcher in Settings.";
            root.state = "failed";
            return;
        }
        try {
            var parsed = JSON.parse(output.text);
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
                throw new Error("Expected a JSON object.");
            if (root.delta && (parsed.record_type !== "delta" || typeof parsed.has_changes !== "boolean"))
                throw new Error("Expected a structured delta report.");
            if (!root.delta && (!Array.isArray(parsed.services) || typeof parsed.queried_domain !== "string"))
                throw new Error("Expected a structured lookup report.");
            root.result = parsed;
            root.rawJson = output.text;
            root.state = "succeeded";
        } catch (error) {
            root.errorMessage = "Invalid structured JSON from Recon: " + error.message;
            root.state = "failed";
        }
    }

    function failedStart() {
        timeout.stop();
        killTimer.stop();
        root.awaitingExit = false;
        if (root.state === "running") {
            root.errorMessage = "Recon could not start. Check that the absolute launcher in Settings exists and is executable.";
            root.state = "failed";
        }
    }

    property Process process: Process {
        command: []
        stdout: StdioCollector { id: output }
        stderr: StdioCollector { id: errors }
        onStarted: root.started = true
        onRunningChanged: if (!running && root.awaitingExit && !root.started) root.failedStart()
        onExited: function(exitCode) { root.finish(exitCode); }
    }

    property Timer timeout: Timer {
        interval: root.timeoutMs
        onTriggered: root.stop("timed-out")
    }

    property Timer killTimer: Timer {
        interval: 1000
        onTriggered: if (root.awaitingExit) process.signal(9)
    }

    Component.onDestruction: if (root.awaitingExit) process.signal(9)
}
