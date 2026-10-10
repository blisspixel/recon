import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root

    // Dimensions for Omarchy panel popup or standalone window
    width: 720
    height: 640
    color: "#181825"
    radius: 12
    border.color: "#313244"
    border.width: 1

    // Public API properties
    property var lookupResult: null
    property var deltaResult: null
    property bool isRunning: false
    property string statusMessage: ""
    property string errorMessage: ""
    property bool deltaMode: false
    property string activeDomain: ""

    // Public signals
    signal requestLookup(string domain, bool delta)
    signal requestCancel()
    signal requestClose()

    // Domain validation function (parity with recon_tool.validator)
    function validateDomainInput(raw) {
        if (!raw || typeof raw !== "string") {
            return { valid: false, error: "A domain is required." };
        }
        var str = raw.trim();
        if (str.length === 0) {
            return { valid: false, error: "A domain is required." };
        }
        if (str.length > 253) {
            return { valid: false, error: "Domain input exceeds maximum length (253 characters)." };
        }
        // Reject shell meta-characters and control characters
        if (/[\s;`$|&><'"\\{}[\]^]/.test(str)) {
            return { valid: false, error: "Domain contains disallowed characters or shell meta-characters." };
        }
        // Strip scheme if present
        if (/^https?:\/\//i.test(str)) {
            str = str.replace(/^https?:\/\//i, "");
        }
        // Strip trailing path, query, or fragment
        str = str.split(/[/?#]/)[0];
        // Strip port suffix
        str = str.replace(/:\d+$/, "");
        // Normalize lowercase
        str = str.toLowerCase();
        // Strip trailing root dot
        str = str.replace(/\.+$/, "");

        // Canonical domain format regex: alphanumeric labels with interior hyphens
        var domainRe = /^(?!-)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$/;
        if (!domainRe.test(str)) {
            return { valid: false, error: "Invalid domain format. Expected format like 'example.com'." };
        }
        // Label length boundaries
        var labels = str.split(".");
        for (var i = 0; i < labels.length; i++) {
            if (labels[i].length === 0 || labels[i].length > 63) {
                return { valid: false, error: "Invalid label length. DNS labels must be 1 to 63 characters." };
            }
        }
        return { valid: true, domain: str };
    }

    // Explicit user action to run lookup (never triggered automatically on clipboard paste)
    function runInspection() {
        if (root.isRunning) {
            return;
        }
        var check = validateDomainInput(domainField.text);
        if (!check.valid) {
            root.errorMessage = check.error;
            root.statusMessage = "";
            return;
        }
        root.errorMessage = "";
        root.statusMessage = "Starting lookup for " + check.domain + "...";
        root.activeDomain = check.domain;
        root.requestLookup(check.domain, root.deltaMode);
    }

    // Explicit user action to cancel running lookup
    function cancelInspection() {
        if (root.isRunning) {
            root.requestCancel();
            root.statusMessage = "Lookup cancelled by operator.";
        }
    }

    // Focus input on load
    Component.onCompleted: {
        domainField.forceActiveFocus();
    }

    // Keyboard shortcuts
    Keys.onEscapePressed: function(event) {
        if (root.isRunning) {
            cancelInspection();
            event.accepted = true;
        } else {
            root.requestClose();
            event.accepted = true;
        }
    }

    Shortcut {
        sequence: "Ctrl+D"
        onActivated: {
            root.deltaMode = !root.deltaMode;
        }
    }

    Shortcut {
        sequence: "Ctrl+L"
        onActivated: {
            domainField.text = "";
            root.lookupResult = null;
            root.deltaResult = null;
            root.errorMessage = "";
            root.statusMessage = "";
            domainField.forceActiveFocus();
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 18
        spacing: 14

        // Top Header Row
        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Text {
                text: "RECON"
                font.bold: true
                font.pixelSize: 18
                color: "#cdd6f4"
                font.letterSpacing: 1.5
            }

            Rectangle {
                color: "#313244"
                radius: 4
                Layout.preferredHeight: 22
                Layout.preferredWidth: hedgedText.implicitWidth + 14

                Text {
                    id: hedgedText
                    anchors.centerIn: parent
                    text: "Public Metadata Observation"
                    font.pixelSize: 11
                    font.weight: Font.DemiBold
                    color: "#89b4fa"
                }
            }

            Item { Layout.fillWidth: true }

            Text {
                text: "Esc: Close | Ctrl+D: Delta | Ctrl+L: Clear"
                font.pixelSize: 11
                color: "#6c7086"
            }
        }

        // Domain Input Bar
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 46
            color: "#1e1e2e"
            radius: 8
            border.color: domainField.activeFocus ? "#89b4fa" : "#313244"
            border.width: 1

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 12
                anchors.rightMargin: 8
                spacing: 8

                Text {
                    text: ">"
                    color: "#89b4fa"
                    font.bold: true
                    font.pixelSize: 15
                }

                TextField {
                    id: domainField
                    Layout.fillWidth: true
                    placeholderText: "Enter domain (e.g. example.com)..."
                    placeholderTextColor: "#585b70"
                    color: "#cdd6f4"
                    font.pixelSize: 14
                    background: null
                    selectByMouse: true
                    enabled: !root.isRunning

                    onAccepted: {
                        root.runInspection();
                    }
                }

                // Delta Mode Toggle Button
                Rectangle {
                    Layout.preferredHeight: 30
                    Layout.preferredWidth: deltaLabel.implicitWidth + 18
                    radius: 6
                    color: root.deltaMode ? "#45475a" : "#181825"
                    border.color: root.deltaMode ? "#89b4fa" : "#313244"
                    border.width: 1

                    Text {
                        id: deltaLabel
                        anchors.centerIn: parent
                        text: "Baseline Delta"
                        font.pixelSize: 11
                        font.weight: Font.DemiBold
                        color: root.deltaMode ? "#89b4fa" : "#a6adc8"
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            root.deltaMode = !root.deltaMode;
                        }
                    }
                }

                // Run / Cancel Button
                Rectangle {
                    Layout.preferredHeight: 30
                    Layout.preferredWidth: 80
                    radius: 6
                    color: root.isRunning ? "#f38ba8" : "#89b4fa"

                    Text {
                        anchors.centerIn: parent
                        text: root.isRunning ? "Cancel" : "Inspect"
                        font.pixelSize: 12
                        font.weight: Font.Bold
                        color: "#11111b"
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            if (root.isRunning) {
                                root.cancelInspection();
                            } else {
                                root.runInspection();
                            }
                        }
                    }
                }
            }
        }

        // Status or Error Banners
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: errorText.text.length > 0 ? errorText.implicitHeight + 16 : 0
            visible: errorText.text.length > 0
            color: "#3e1f29"
            radius: 6
            border.color: "#f38ba8"
            border.width: 1

            Text {
                id: errorText
                anchors.fill: parent
                anchors.margins: 8
                text: root.errorMessage
                color: "#f38ba8"
                font.pixelSize: 12
                wrapMode: Text.WordWrap
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 32
            visible: root.isRunning || (root.statusMessage.length > 0 && root.errorMessage.length === 0)
            color: "#1e1e2e"
            radius: 6

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 12
                anchors.rightMargin: 12
                spacing: 8

                BusyIndicator {
                    Layout.preferredWidth: 16
                    Layout.preferredHeight: 16
                    running: root.isRunning
                    visible: root.isRunning
                }

                Text {
                    Layout.fillWidth: true
                    text: root.statusMessage
                    color: root.isRunning ? "#89b4fa" : "#a6adc8"
                    font.pixelSize: 12
                    elide: Text.ElideRight
                }
            }
        }

        // Main Results Area
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
            ScrollBar.vertical.policy: ScrollBar.AsNeeded

            ColumnLayout {
                width: parent.width
                spacing: 14

                // Empty State / Instructions
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 260
                    color: "#1e1e2e"
                    radius: 8
                    visible: root.lookupResult === null && root.deltaResult === null && !root.isRunning

                    ColumnLayout {
                        anchors.centerIn: parent
                        spacing: 10

                        Text {
                            text: "Ready for Domain Inspection"
                            font.bold: true
                            font.pixelSize: 15
                            color: "#cdd6f4"
                            Layout.alignment: Qt.AlignHCenter
                        }

                        Text {
                            text: "Type an apex domain above and press Enter to query public metadata.\nRecon reads public DNS, certificate transparency, and unauthenticated endpoints.\nDefault checks make zero active port scans or application crawls."
                            font.pixelSize: 12
                            color: "#a6adc8"
                            horizontalAlignment: Text.AlignHCenter
                            Layout.alignment: Qt.AlignHCenter
                        }

                        Rectangle {
                            Layout.topMargin: 10
                            Layout.alignment: Qt.AlignHCenter
                            color: "#313244"
                            radius: 4
                            Layout.preferredWidth: 320
                            Layout.preferredHeight: 30

                            Text {
                                anchors.centerIn: parent
                                text: "Observation only: results are not a security verdict."
                                font.pixelSize: 11
                                color: "#f9e2af"
                            }
                        }
                    }
                }

                // Standard Lookup Overview Card
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: overviewCol.implicitHeight + 24
                    color: "#1e1e2e"
                    radius: 8
                    visible: root.lookupResult !== null

                    ColumnLayout {
                        id: overviewCol
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 10

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 10

                            Text {
                                text: root.lookupResult ? (root.lookupResult.queried_domain || "") : ""
                                font.bold: true
                                font.pixelSize: 16
                                color: "#cdd6f4"
                            }

                            Text {
                                text: root.lookupResult && root.lookupResult.display_name && root.lookupResult.display_name !== root.lookupResult.queried_domain ? "(" + root.lookupResult.display_name + ")" : ""
                                font.pixelSize: 13
                                color: "#a6adc8"
                                visible: text.length > 0
                            }

                            Item { Layout.fillWidth: true }

                            // Confidence Badge
                            Rectangle {
                                Layout.preferredHeight: 22
                                Layout.preferredWidth: confText.implicitWidth + 14
                                radius: 4
                                color: {
                                    var c = root.lookupResult ? (root.lookupResult.confidence || "low") : "low";
                                    return c === "high" ? "#1e3a2f" : (c === "medium" ? "#3e321e" : "#2f313d");
                                }
                                border.color: {
                                    var c = root.lookupResult ? (root.lookupResult.confidence || "low") : "low";
                                    return c === "high" ? "#a6e3a1" : (c === "medium" ? "#f9e2af" : "#6c7086");
                                }
                                border.width: 1

                                Text {
                                    id: confText
                                    anchors.centerIn: parent
                                    text: {
                                        var c = root.lookupResult ? (root.lookupResult.confidence || "low") : "low";
                                        var dots = c === "high" ? "●●●" : (c === "medium" ? "●●○" : "●○○");
                                        return dots + " " + c.charAt(0).toUpperCase() + c.slice(1) + " Confidence";
                                    }
                                    font.pixelSize: 11
                                    font.weight: Font.DemiBold
                                    color: {
                                        var c = root.lookupResult ? (root.lookupResult.confidence || "low") : "low";
                                        return c === "high" ? "#a6e3a1" : (c === "medium" ? "#f9e2af" : "#cdd6f4");
                                    }
                                }
                            }
                        }

                        // Provider & Tenant Row
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 16

                            ColumnLayout {
                                spacing: 2
                                Text { text: "PROVIDER"; font.pixelSize: 10; font.bold: true; color: "#6c7086" }
                                Text {
                                    text: root.lookupResult ? (root.lookupResult.provider || "None observed") : ""
                                    font.pixelSize: 13
                                    font.weight: Font.DemiBold
                                    color: "#cdd6f4"
                                }
                            }

                            ColumnLayout {
                                spacing: 2
                                visible: root.lookupResult && root.lookupResult.tenant_id
                                Text { text: "TENANT ID"; font.pixelSize: 10; font.bold: true; color: "#6c7086" }
                                Text {
                                    text: root.lookupResult && root.lookupResult.tenant_id ? root.lookupResult.tenant_id : ""
                                    font.pixelSize: 12
                                    font.family: "monospace"
                                    color: "#89b4fa"
                                }
                            }

                            ColumnLayout {
                                spacing: 2
                                Text { text: "EMAIL SECURITY"; font.pixelSize: 10; font.bold: true; color: "#6c7086" }
                                Text {
                                    text: {
                                        if (!root.lookupResult) return "0/5";
                                        var score = root.lookupResult.email_security_score;
                                        return (score !== undefined && score !== null ? score : "0") + "/5";
                                    }
                                    font.pixelSize: 13
                                    font.weight: Font.DemiBold
                                    color: "#a6e3a1"
                                }
                            }

                            ColumnLayout {
                                spacing: 2
                                Text { text: "CT SUBDOMAINS"; font.pixelSize: 10; font.bold: true; color: "#6c7086" }
                                Text {
                                    text: root.lookupResult ? (root.lookupResult.ct_subdomain_count || 0).toString() : "0"
                                    font.pixelSize: 13
                                    color: "#cdd6f4"
                                }
                            }
                        }

                        // Degraded sources warning if present
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: degradedCol.implicitHeight + 12
                            visible: root.lookupResult && root.lookupResult.degraded_sources && root.lookupResult.degraded_sources.length > 0
                            color: "#2f281e"
                            radius: 6
                            border.color: "#f9e2af"
                            border.width: 1

                            ColumnLayout {
                                id: degradedCol
                                anchors.fill: parent
                                anchors.margins: 6
                                spacing: 2

                                Text {
                                    text: "Degraded sources: " + (root.lookupResult && root.lookupResult.degraded_sources ? root.lookupResult.degraded_sources.join(", ") : "")
                                    font.pixelSize: 11
                                    font.weight: Font.DemiBold
                                    color: "#f9e2af"
                                }
                                Text {
                                    text: "Observations reflect available public records; unreached sources are surfaced explicitly rather than assumed absent."
                                    font.pixelSize: 10
                                    color: "#bac2de"
                                }
                            }
                        }
                    }
                }

                // Observed Services List
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: servicesCol.implicitHeight + 24
                    color: "#1e1e2e"
                    radius: 8
                    visible: root.lookupResult !== null && root.lookupResult.services && root.lookupResult.services.length > 0

                    ColumnLayout {
                        id: servicesCol
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8

                        Text {
                            text: "OBSERVED SERVICES (" + (root.lookupResult && root.lookupResult.services ? root.lookupResult.services.length : 0) + ")"
                            font.pixelSize: 11
                            font.bold: true
                            color: "#89b4fa"
                        }

                        Flow {
                            Layout.fillWidth: true
                            spacing: 6

                            Repeater {
                                model: root.lookupResult ? (root.lookupResult.services || []) : []
                                delegate: Rectangle {
                                    height: 24
                                    width: serviceText.implicitWidth + 14
                                    radius: 4
                                    color: "#313244"
                                    border.color: "#45475a"
                                    border.width: 1

                                    Text {
                                        id: serviceText
                                        anchors.centerIn: parent
                                        text: modelData
                                        font.pixelSize: 11
                                        color: "#cdd6f4"
                                    }
                                }
                            }
                        }
                    }
                }

                // Insights List
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: insightsCol.implicitHeight + 24
                    color: "#1e1e2e"
                    radius: 8
                    visible: root.lookupResult !== null && root.lookupResult.insights && root.lookupResult.insights.length > 0

                    ColumnLayout {
                        id: insightsCol
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8

                        Text {
                            text: "HEDGED OBSERVATIONS"
                            font.pixelSize: 11
                            font.bold: true
                            color: "#89b4fa"
                        }

                        Repeater {
                            model: root.lookupResult ? (root.lookupResult.insights || []) : []
                            delegate: RowLayout {
                                Layout.fillWidth: true
                                spacing: 8

                                Text {
                                    text: "•"
                                    color: "#89b4fa"
                                    font.pixelSize: 13
                                    Layout.alignment: Qt.AlignTop
                                }

                                Text {
                                    Layout.fillWidth: true
                                    text: modelData
                                    color: "#bac2de"
                                    font.pixelSize: 12
                                    wrapMode: Text.WordWrap
                                }
                            }
                        }
                    }
                }

                // Baseline Delta Changes Card
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: deltaCol.implicitHeight + 24
                    color: "#1e1e2e"
                    radius: 8
                    visible: root.deltaResult !== null

                    ColumnLayout {
                        id: deltaCol
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 10

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8

                            Text {
                                text: "BASELINE DRIFT ANALYSIS"
                                font.pixelSize: 11
                                font.bold: true
                                color: "#f9e2af"
                            }

                            Item { Layout.fillWidth: true }

                            Rectangle {
                                Layout.preferredHeight: 20
                                Layout.preferredWidth: deltaStatusText.implicitWidth + 12
                                radius: 4
                                color: root.deltaResult && root.deltaResult.has_changes ? "#3e1f29" : "#1e3a2f"

                                Text {
                                    id: deltaStatusText
                                    anchors.centerIn: parent
                                    text: root.deltaResult && root.deltaResult.has_changes ? "Changes Observed" : "No Changes"
                                    font.pixelSize: 10
                                    font.bold: true
                                    color: root.deltaResult && root.deltaResult.has_changes ? "#f38ba8" : "#a6e3a1"
                                }
                            }
                        }

                        // Added Services
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4
                            visible: root.deltaResult && root.deltaResult.added_services && root.deltaResult.added_services.length > 0

                            Text { text: "Added Services:"; font.pixelSize: 11; color: "#a6e3a1"; font.bold: true }

                            Flow {
                                Layout.fillWidth: true
                                spacing: 6
                                Repeater {
                                    model: root.deltaResult ? (root.deltaResult.added_services || []) : []
                                    delegate: Rectangle {
                                        height: 22
                                        width: addedText.implicitWidth + 12
                                        radius: 4
                                        color: "#1e3a2f"
                                        Text { id: addedText; anchors.centerIn: parent; text: "+ " + modelData; font.pixelSize: 11; color: "#a6e3a1" }
                                    }
                                }
                            }
                        }

                        // Removed Services
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4
                            visible: root.deltaResult && root.deltaResult.removed_services && root.deltaResult.removed_services.length > 0

                            Text { text: "Removed Services:"; font.pixelSize: 11; color: "#f38ba8"; font.bold: true }

                            Flow {
                                Layout.fillWidth: true
                                spacing: 6
                                Repeater {
                                    model: root.deltaResult ? (root.deltaResult.removed_services || []) : []
                                    delegate: Rectangle {
                                        height: 22
                                        width: removedText.implicitWidth + 12
                                        radius: 4
                                        color: "#3e1f29"
                                        Text { id: removedText; anchors.centerIn: parent; text: "- " + modelData; font.pixelSize: 11; color: "#f38ba8" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
