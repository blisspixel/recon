import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "ThemePalette.js" as ThemePalette

Rectangle {
    id: root

    // Dimensions for Omarchy panel popup or standalone window
    width: 720
    height: 640
    color: root.colors.background
    radius: 12
    border.color: root.colors.border
    border.width: 1

    // Public API properties
    property var lookupResult: null
    property var deltaResult: null
    property bool isRunning: false
    property string statusMessage: ""
    property string errorMessage: ""
    property bool deltaMode: false
    property string activeDomain: ""
    property bool canRun: true
    property bool noBaseline: false
    property string rawJson: ""
    property string fontFamily: "Sans Serif"
    // Standalone previews use a light or dark fallback set picked by
    // lightTheme; inside Omarchy the panel supplies live theme roles.
    property bool lightTheme: false
    property var colors: root.lightTheme ? ThemePalette.fallback.light : ThemePalette.fallback.dark
    readonly property var incompleteDelta: root.deltaResult ? root.deltaResult.incomplete_comparison : null
    readonly property bool deltaComparisonIncomplete: !!root.incompleteDelta

    component ActionButton: Button {
        font.family: root.fontFamily
        palette.button: root.colors.surface
        palette.buttonText: root.colors.foreground
        palette.highlight: root.colors.accent
        palette.highlightedText: root.colors.onAccent
    }

    function deltaFieldSuppressed(field) {
        var fields = root.incompleteDelta ? root.incompleteDelta.suppressed_fields : [];
        return !!fields && fields.indexOf(field) !== -1;
    }

    function deltaCompletionMessage(report) {
        if (report.incomplete_comparison) {
            return "Baseline comparison incomplete (" + (report.has_changes
                ? "changes observed in comparable fields" : "some fields not compared") + ").";
        }
        return "Baseline comparison complete (" + (report.has_changes ? "changes observed" : "unchanged") + ").";
    }

    // Public signals
    signal requestLookup(string domain, bool delta)
    signal requestCancel()
    signal requestClose()
    signal requestSettings()
    signal requestTerminal(string domain)

    function prefill(domain, mode) {
        if (typeof domain === "string")
            domainField.text = domain;
        root.deltaMode = mode === "delta";
        domainField.forceActiveFocus();
    }

    function copyJson() {
        if (root.rawJson.length > 0) {
            copyBuffer.selectAll();
            copyBuffer.copy();
            copyBuffer.deselect();
        }
    }

    function openTerminal() {
        var check = validateDomainInput(domainField.text);
        if (check.valid && root.canRun && !root.isRunning)
            root.requestTerminal(check.domain);
        else if (!check.valid)
            root.errorMessage = check.error;
    }

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
        if (root.isRunning || !root.canRun) {
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

        RowLayout {
            Layout.fillWidth: true
            ActionButton { text: "Settings"; enabled: !root.isRunning; onClicked: root.requestSettings() }
            ActionButton { text: "Copy JSON"; enabled: root.rawJson.length > 0 && !root.isRunning; onClicked: root.copyJson() }
            ActionButton { text: "Open in terminal"; enabled: root.canRun && !root.isRunning; onClicked: root.openTerminal() }
            Item { Layout.fillWidth: true }
        }

        ActionButton {
            objectName: "recordBaseline"
            text: "Record baseline"
            visible: root.noBaseline
            enabled: root.canRun && !root.isRunning
            onClicked: {
                root.deltaMode = false;
                root.requestLookup(root.activeDomain, false);
            }
        }

        // Top Header Row
        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Text { font.family: root.fontFamily;
                text: "RECON"
                font.bold: true
                font.pixelSize: 18
                color: root.colors.foreground
                font.letterSpacing: 1.5
            }

            Rectangle {
                color: root.colors.border
                radius: 4
                Layout.preferredHeight: 22
                Layout.preferredWidth: hedgedText.implicitWidth + 14

                Text { font.family: root.fontFamily;
                    id: hedgedText
                    anchors.centerIn: parent
                    text: "Public Metadata Observation"
                    font.pixelSize: 11
                    font.weight: Font.DemiBold
                    color: root.colors.accent
                }
            }

            Item { Layout.fillWidth: true }

            Text { font.family: root.fontFamily;
                text: "Esc: Close | Ctrl+D: Delta | Ctrl+L: Clear"
                font.pixelSize: 11
                color: root.colors.muted
            }
        }

        // Domain Input Bar
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 46
            color: root.colors.surface
            radius: 8
            border.color: domainField.activeFocus ? root.colors.accent : root.colors.border
            border.width: 1

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 12
                anchors.rightMargin: 8
                spacing: 8

                Text { font.family: root.fontFamily;
                    text: ">"
                    color: root.colors.accent
                    font.bold: true
                    font.pixelSize: 15
                }

                TextField {
                    font.family: root.fontFamily
                    id: domainField
                    Layout.fillWidth: true
                    placeholderText: "Enter domain (e.g. example.com)..."
                    placeholderTextColor: root.colors.muted
                    color: root.colors.foreground
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
                    color: root.deltaMode ? root.colors.border : root.colors.background
                    border.color: root.deltaMode ? root.colors.accent : root.colors.border
                    border.width: 1

                    Text { font.family: root.fontFamily;
                        id: deltaLabel
                        anchors.centerIn: parent
                        text: "Baseline Delta"
                        font.pixelSize: 11
                        font.weight: Font.DemiBold
                        color: root.deltaMode ? root.colors.accent : root.colors.secondary
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
                    color: root.isRunning ? root.colors.error : root.colors.accent

                    Text { font.family: root.fontFamily;
                        anchors.centerIn: parent
                        text: root.isRunning ? "Cancel" : "Inspect"
                        font.pixelSize: 12
                        font.weight: Font.Bold
                        color: root.colors.onAccent
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
            color: root.colors.errorFill
            radius: 6
            border.color: root.colors.error
            border.width: 1

            Text { font.family: root.fontFamily;
                id: errorText
                anchors.fill: parent
                anchors.margins: 8
                text: root.errorMessage
                color: root.colors.error
                font.pixelSize: 12
                wrapMode: Text.WordWrap
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 32
            visible: root.isRunning || (root.statusMessage.length > 0 && root.errorMessage.length === 0)
            color: root.colors.surface
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

                Text { font.family: root.fontFamily;
                    Layout.fillWidth: true
                    text: root.statusMessage
                    color: root.isRunning ? root.colors.accent : root.colors.secondary
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
                    color: root.colors.surface
                    radius: 8
                    visible: root.lookupResult === null && root.deltaResult === null && !root.isRunning

                    ColumnLayout {
                        anchors.centerIn: parent
                        spacing: 10

                        Text { font.family: root.fontFamily;
                            text: "Ready for Domain Inspection"
                            font.bold: true
                            font.pixelSize: 15
                            color: root.colors.foreground
                            Layout.alignment: Qt.AlignHCenter
                        }

                        Text { font.family: root.fontFamily;
                            text: "Type an apex domain above and press Enter to query public metadata.\nRecon reads public DNS, certificate transparency, and unauthenticated endpoints.\nDefault checks make zero active port scans or application crawls."
                            font.pixelSize: 12
                            color: root.colors.secondary
                            horizontalAlignment: Text.AlignHCenter
                            Layout.alignment: Qt.AlignHCenter
                        }

                        Rectangle {
                            Layout.topMargin: 10
                            Layout.alignment: Qt.AlignHCenter
                            color: root.colors.border
                            radius: 4
                            Layout.preferredWidth: 320
                            Layout.preferredHeight: 30

                            Text { font.family: root.fontFamily;
                                anchors.centerIn: parent
                                text: "Observation only: results are not a security verdict."
                                font.pixelSize: 11
                                color: root.colors.warning
                            }
                        }
                    }
                }

                // Standard Lookup Overview Card
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: overviewCol.implicitHeight + 24
                    color: root.colors.surface
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

                            Text { font.family: root.fontFamily;
                                objectName: "queriedDomain"
                                text: root.lookupResult ? (root.lookupResult.queried_domain || "") : ""
                                font.bold: true
                                font.pixelSize: 16
                                color: root.colors.foreground
                            }

                            Text { font.family: root.fontFamily;
                                objectName: "displayName"
                                text: root.lookupResult && root.lookupResult.display_name && root.lookupResult.display_name !== root.lookupResult.queried_domain ? "(" + root.lookupResult.display_name + ")" : ""
                                font.pixelSize: 13
                                color: root.colors.secondary
                                visible: text.length > 0
                            }

                            Item { Layout.fillWidth: true }

                            // Confidence badge: High is success, Medium info, Low warning, as in the CLI.
                            Rectangle {
                                Layout.preferredHeight: 22
                                Layout.preferredWidth: confText.implicitWidth + 14
                                radius: 4
                                color: {
                                    var c = root.lookupResult ? (root.lookupResult.confidence || "low") : "low";
                                    return c === "high" ? root.colors.successFill : (c === "medium" ? root.colors.infoFill : root.colors.warningFill);
                                }
                                border.color: {
                                    var c = root.lookupResult ? (root.lookupResult.confidence || "low") : "low";
                                    return c === "high" ? root.colors.success : (c === "medium" ? root.colors.info : root.colors.warning);
                                }
                                border.width: 1

                                Text { font.family: root.fontFamily;
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
                                        return c === "high" ? root.colors.success : (c === "medium" ? root.colors.info : root.colors.warning);
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
                                Text { font.family: root.fontFamily; text: "PROVIDER"; font.pixelSize: 10; font.bold: true; color: root.colors.muted }
                                Text { font.family: root.fontFamily;
                                    text: root.lookupResult ? (root.lookupResult.provider || "None observed") : ""
                                    font.pixelSize: 13
                                    font.weight: Font.DemiBold
                                    color: root.colors.foreground
                                }
                            }

                            ColumnLayout {
                                spacing: 2
                                visible: root.lookupResult && root.lookupResult.tenant_id
                                Text { font.family: root.fontFamily; text: "TENANT ID"; font.pixelSize: 10; font.bold: true; color: root.colors.muted }
                                Text {
                                    text: root.lookupResult && root.lookupResult.tenant_id ? root.lookupResult.tenant_id : ""
                                    font.pixelSize: 12
                                    font.family: "monospace"
                                    color: root.colors.accent
                                }
                            }

                            ColumnLayout {
                                spacing: 2
                                Text { font.family: root.fontFamily; text: "EMAIL SECURITY"; font.pixelSize: 10; font.bold: true; color: root.colors.muted }
                                Text { font.family: root.fontFamily;
                                    text: {
                                        if (!root.lookupResult) return "0/5";
                                        var score = root.lookupResult.email_security_score;
                                        return (score !== undefined && score !== null ? score : "0") + "/5";
                                    }
                                    font.pixelSize: 13
                                    font.weight: Font.DemiBold
                                    color: root.colors.success
                                }
                            }

                            ColumnLayout {
                                spacing: 2
                                Text { font.family: root.fontFamily; text: "CT SUBDOMAINS"; font.pixelSize: 10; font.bold: true; color: root.colors.muted }
                                Text { font.family: root.fontFamily;
                                    text: root.lookupResult ? (root.lookupResult.ct_subdomain_count || 0).toString() : "0"
                                    font.pixelSize: 13
                                    color: root.colors.foreground
                                }
                            }
                        }

                        // Degraded sources warning if present
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: degradedCol.implicitHeight + 12
                            visible: root.lookupResult && root.lookupResult.degraded_sources && root.lookupResult.degraded_sources.length > 0
                            color: root.colors.warningFill
                            radius: 6
                            border.color: root.colors.warning
                            border.width: 1

                            ColumnLayout {
                                id: degradedCol
                                anchors.fill: parent
                                anchors.margins: 6
                                spacing: 2

                                Text { font.family: root.fontFamily;
                                    text: "Degraded sources: " + (root.lookupResult && root.lookupResult.degraded_sources ? root.lookupResult.degraded_sources.join(", ") : "")
                                    font.pixelSize: 11
                                    font.weight: Font.DemiBold
                                    color: root.colors.warning
                                }
                                Text { font.family: root.fontFamily;
                                    text: "Observations reflect available public records; unreached sources are surfaced explicitly rather than assumed absent."
                                    font.pixelSize: 10
                                    color: root.colors.secondary
                                }
                            }
                        }
                    }
                }

                // Observed Services List
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: servicesCol.implicitHeight + 24
                    color: root.colors.surface
                    radius: 8
                    visible: root.lookupResult !== null && root.lookupResult.services && root.lookupResult.services.length > 0

                    ColumnLayout {
                        id: servicesCol
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8

                        Text { font.family: root.fontFamily;
                            text: "OBSERVED SERVICES (" + (root.lookupResult && root.lookupResult.services ? root.lookupResult.services.length : 0) + ")"
                            font.pixelSize: 11
                            font.bold: true
                            color: root.colors.accent
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
                                    color: root.colors.border
                                    border.color: root.colors.border
                                    border.width: 1

                                    Text { font.family: root.fontFamily;
                                        id: serviceText
                                        anchors.centerIn: parent
                                        text: modelData
                                        font.pixelSize: 11
                                        color: root.colors.foreground
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
                    color: root.colors.surface
                    radius: 8
                    visible: root.lookupResult !== null && root.lookupResult.insights && root.lookupResult.insights.length > 0

                    ColumnLayout {
                        id: insightsCol
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8

                        Text { font.family: root.fontFamily;
                            text: "HEDGED OBSERVATIONS"
                            font.pixelSize: 11
                            font.bold: true
                            color: root.colors.accent
                        }

                        Repeater {
                            model: root.lookupResult ? (root.lookupResult.insights || []) : []
                            delegate: RowLayout {
                                Layout.fillWidth: true
                                spacing: 8

                                Text { font.family: root.fontFamily;
                                    text: "•"
                                    color: root.colors.accent
                                    font.pixelSize: 13
                                    Layout.alignment: Qt.AlignTop
                                }

                                Text { font.family: root.fontFamily;
                                    Layout.fillWidth: true
                                    text: modelData
                                    color: root.colors.secondary
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
                    color: root.colors.surface
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

                            Text { font.family: root.fontFamily;
                                text: "BASELINE DRIFT ANALYSIS"
                                font.pixelSize: 11
                                font.bold: true
                                color: root.colors.warning
                            }

                            Item { Layout.fillWidth: true }

                            Rectangle {
                                Layout.preferredHeight: 20
                                Layout.preferredWidth: deltaStatusText.implicitWidth + 12
                                radius: 4
                                color: root.deltaComparisonIncomplete ? root.colors.warningFill : (root.deltaResult && root.deltaResult.has_changes ? root.colors.errorFill : root.colors.successFill)

                                Text { font.family: root.fontFamily;
                                    id: deltaStatusText
                                    anchors.centerIn: parent
                                    text: root.deltaComparisonIncomplete ? "Partial comparison" : (root.deltaResult && root.deltaResult.has_changes ? "Changes Observed" : "No Changes")
                                    font.pixelSize: 10
                                    font.bold: true
                                    color: root.deltaComparisonIncomplete ? root.colors.warning : (root.deltaResult && root.deltaResult.has_changes ? root.colors.error : root.colors.success)
                                }
                            }
                        }

                        Text { font.family: root.fontFamily;
                            Layout.fillWidth: true
                            visible: root.deltaComparisonIncomplete && !!root.incompleteDelta.degraded_sources && root.incompleteDelta.degraded_sources.length > 0
                            text: "Degraded sources: " + (root.incompleteDelta && root.incompleteDelta.degraded_sources ? root.incompleteDelta.degraded_sources.join(", ") : "")
                            wrapMode: Text.Wrap
                            font.pixelSize: 11
                            color: root.colors.warning
                        }

                        Text { font.family: root.fontFamily;
                            Layout.fillWidth: true
                            visible: root.deltaComparisonIncomplete && !!root.incompleteDelta.suppressed_fields && root.incompleteDelta.suppressed_fields.length > 0
                            text: "Not compared: " + (root.incompleteDelta && root.incompleteDelta.suppressed_fields ? root.incompleteDelta.suppressed_fields.join(", ") : "")
                            wrapMode: Text.Wrap
                            font.pixelSize: 11
                            color: root.colors.warning
                        }

                        // Added Services
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4
                            visible: !!root.deltaResult && (root.deltaFieldSuppressed("added_services") || !!root.deltaResult.added_services && root.deltaResult.added_services.length > 0)

                            Text { font.family: root.fontFamily;
                                text: root.deltaFieldSuppressed("added_services") ? "Added Services: not compared" : "Added Services:"
                                font.pixelSize: 11
                                color: root.deltaFieldSuppressed("added_services") ? root.colors.warning : root.colors.success
                                font.bold: true
                            }

                            Flow {
                                Layout.fillWidth: true
                                spacing: 6
                                Repeater {
                                    model: root.deltaResult && !root.deltaFieldSuppressed("added_services") ? (root.deltaResult.added_services || []) : []
                                    delegate: Rectangle {
                                        height: 22
                                        width: addedText.implicitWidth + 12
                                        radius: 4
                                        color: root.colors.successFill
                                        Text { font.family: root.fontFamily; id: addedText; anchors.centerIn: parent; text: "+ " + modelData; font.pixelSize: 11; color: root.colors.success }
                                    }
                                }
                            }
                        }

                        // Removed Services
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4
                            visible: !!root.deltaResult && (root.deltaFieldSuppressed("removed_services") || !!root.deltaResult.removed_services && root.deltaResult.removed_services.length > 0)

                            Text { font.family: root.fontFamily;
                                text: root.deltaFieldSuppressed("removed_services") ? "Removed Services: not compared" : "Removed Services:"
                                font.pixelSize: 11
                                color: root.deltaFieldSuppressed("removed_services") ? root.colors.warning : root.colors.error
                                font.bold: true
                            }

                            Flow {
                                Layout.fillWidth: true
                                spacing: 6
                                Repeater {
                                    model: root.deltaResult && !root.deltaFieldSuppressed("removed_services") ? (root.deltaResult.removed_services || []) : []
                                    delegate: Rectangle {
                                        height: 22
                                        width: removedText.implicitWidth + 12
                                        radius: 4
                                        color: root.colors.errorFill
                                        Text { font.family: root.fontFamily; id: removedText; anchors.centerIn: parent; text: "- " + modelData; font.pixelSize: 11; color: root.colors.error }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    TextEdit {
        id: copyBuffer
        objectName: "rawJsonCopy"
        visible: false
        readOnly: true
        textFormat: TextEdit.PlainText
        text: root.rawJson
    }
}
