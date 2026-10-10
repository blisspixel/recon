import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io

// Omarchy Bar Widget Entry Point
Item {
    id: widgetRoot

    implicitWidth: barRow.implicitWidth + 16
    implicitHeight: 32

    property bool isPanelOpen: false

    // Process executor for Omarchy Quickshell
    Process {
        id: reconProcess
        command: []
        running: false

        stdout: StdioCollector {
            id: stdoutCollector
        }

        stderr: StdioCollector {
            id: stderrCollector
        }

        onExited: function(exitCode) {
            timeoutTimer.stop();
            reconView.isRunning = false;

            var outText = stdoutCollector.text || "";
            var errText = stderrCollector.text || "";

            if (exitCode === 0 && outText.trim().length > 0) {
                try {
                    var parsed = JSON.parse(outText);
                    if (parsed.record_type === "delta") {
                        reconView.deltaResult = parsed;
                        reconView.statusMessage = "Baseline comparison complete (" + (parsed.has_changes ? "changes observed" : "unchanged") + ").";
                    } else {
                        reconView.lookupResult = parsed;
                        reconView.statusMessage = "Public metadata observation complete (" + (parsed.services ? parsed.services.length : 0) + " services observed).";
                    }
                    reconView.errorMessage = "";
                } catch (e) {
                    reconView.errorMessage = "Failed to parse structured JSON output from recon: " + e.message;
                    reconView.statusMessage = "";
                }
            } else {
                reconView.errorMessage = errText.trim().length > 0 ? errText.trim() : "recon exited with non-zero status code: " + exitCode;
                reconView.statusMessage = "";
            }
        }
    }

    // Bounded timeout guard (30 seconds)
    Timer {
        id: timeoutTimer
        interval: 30000
        repeat: false
        onTriggered: {
            if (reconProcess.running) {
                reconProcess.running = false;
                reconView.isRunning = false;
                reconView.errorMessage = "Lookup timed out after 30 seconds. Bounded DNS and HTTPS queries halted.";
                reconView.statusMessage = "";
            }
        }
    }

    // Bar button representation
    Rectangle {
        id: barButton
        anchors.fill: parent
        color: barMouseArea.containsMouse ? "#313244" : (widgetRoot.isPanelOpen ? "#45475a" : "transparent")
        radius: 6

        RowLayout {
            id: barRow
            anchors.centerIn: parent
            spacing: 6

            Rectangle {
                width: 8
                height: 8
                radius: 4
                color: reconView.isRunning ? "#f9e2af" : "#89b4fa"
            }

            Text {
                text: "Recon"
                font.bold: true
                font.pixelSize: 12
                color: "#cdd6f4"
            }
        }

        MouseArea {
            id: barMouseArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
                panelPopup.visible = !panelPopup.visible;
                widgetRoot.isPanelOpen = panelPopup.visible;
            }
        }
    }

    // Popup window containing the full keyboard-first ReconView
    PopupWindow {
        id: panelPopup
        visible: false
        anchor.window: widgetRoot.Window.window
        anchor.rect.x: widgetRoot.x
        anchor.rect.y: widgetRoot.height + 6
        width: 720
        height: 640

        ReconView {
            id: reconView
            anchors.fill: parent

            onRequestLookup: function(domain, delta) {
                reconView.isRunning = true;
                reconView.errorMessage = "";
                reconView.statusMessage = "Querying public metadata for " + domain + "...";

                // Direct argument list execution; no shell interpolation
                var cmd = delta ? ["recon", "delta", domain, "--json"] : ["recon", domain, "--json"];
                reconProcess.command = cmd;
                reconProcess.running = true;
                timeoutTimer.restart();
            }

            onRequestCancel: function() {
                timeoutTimer.stop();
                if (reconProcess.running) {
                    reconProcess.running = false;
                }
                reconView.isRunning = false;
                reconView.statusMessage = "Lookup cancelled.";
            }

            onRequestClose: function() {
                panelPopup.visible = false;
                widgetRoot.isPanelOpen = false;
            }
        }

        onVisibleChanged: {
            widgetRoot.isPanelOpen = panelPopup.visible;
        }
    }
}
