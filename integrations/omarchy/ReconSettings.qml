import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "Settings.js" as Settings

ColumnLayout {
    id: root
    property var entry: ({})
    property var original: ({})
    property string errorMessage: ""
    property bool busy: false
    signal saveRequested(var patch)
    signal dismissRequested()

    function edit(value) {
        root.entry = value;
        commandField.text = Settings.owns(value, "reconCommand") ? String(value.reconCommand) : "";
        timeoutField.text = String(Settings.owns(value, "timeoutSec") ? value.timeoutSec : 30);
        modeField.currentIndex = !Settings.owns(value, "defaultMode") || value.defaultMode === "lookup" ? 0 : (value.defaultMode === "delta" ? 1 : -1);
        root.original = {reconCommand: commandField.text, timeoutSec: timeoutField.text, defaultMode: modeField.currentIndex};
        root.errorMessage = "";
    }

    function save() {
        if (root.busy)
            return;
        try {
            if (!/^\d+$/.test(timeoutField.text))
                throw new Error("Timeout must be an integer from 10 to 120 seconds.");
            var draft = {reconCommand: commandField.text, timeoutSec: Number(timeoutField.text), defaultMode: modeField.currentIndex === 0 ? "lookup" : (modeField.currentIndex === 1 ? "delta" : "")};
            Settings.validate(draft);
            var patch = ({});
            if (commandField.text !== root.original.reconCommand)
                patch.reconCommand = draft.reconCommand;
            if (timeoutField.text !== root.original.timeoutSec)
                patch.timeoutSec = draft.timeoutSec;
            if (modeField.currentIndex !== root.original.defaultMode)
                patch.defaultMode = draft.defaultMode;
            root.errorMessage = "";
            root.saveRequested(patch);
        } catch (error) {
            root.errorMessage = error.message;
        }
    }

    spacing: 12
    Label { text: "Recon settings"; font.bold: true; font.pixelSize: 20 }
    Label {
        text: "Stored in this plugin's inline Omarchy entry. Saving settings does not run a lookup."
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
    }
    Label { text: "Absolute Recon launcher" }
    TextField {
        id: commandField
        objectName: "reconCommand"
        Layout.fillWidth: true
        placeholderText: "/home/you/.local/bin/recon"
        enabled: !root.busy
    }
    Label { text: "Timeout in seconds (10 to 120)" }
    TextField {
        id: timeoutField
        objectName: "timeoutSec"
        Layout.fillWidth: true
        enabled: !root.busy
        inputMethodHints: Qt.ImhDigitsOnly
    }
    Label { text: "Default mode" }
    ComboBox {
        id: modeField
        objectName: "defaultMode"
        model: ["Lookup", "Delta"]
        enabled: !root.busy
    }
    Label {
        text: root.errorMessage
        visible: text.length > 0
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
    }
    RowLayout {
        Button { text: root.busy ? "Saving..." : "Save"; enabled: !root.busy; onClicked: root.save() }
        Button { text: "Back"; enabled: !root.busy; onClicked: root.dismissRequested() }
    }
    Item { Layout.fillHeight: true }
}
