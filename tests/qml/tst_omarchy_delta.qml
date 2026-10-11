import QtQuick
import QtTest
import "../../integrations/omarchy" as Recon

Item {
    width: 900
    height: 800

    Recon.ReconView { id: view }

    TestCase {
        name: "OmarchyDelta"
        when: windowShown

        function init() {
            view.deltaResult = null;
        }

        function findText(item, expected) {
            if (item.text !== undefined && item.text === expected)
                return item;
            for (var i = 0; i < item.children.length; i++) {
                var found = findText(item.children[i], expected);
                if (found)
                    return found;
            }
            return null;
        }

        function test_partial_without_changes() {
            view.deltaResult = {
                has_changes: false, added_services: [], removed_services: [],
                incomplete_comparison: {
                    degraded_sources: ["crt.sh", "dns:dkim"],
                    suppressed_fields: ["added_services", "changed_confidence"]
                }
            };
            wait(0);
            var badge = findText(view, "Partial comparison");
            verify(badge !== null, "Incomplete comparison must have a partial badge");
            verify(badge.visible);
            compare(badge.color.toString(), "#f9e2af");
            compare(badge.parent.color.toString(), "#3d3525");
            verify(findText(view, "No Changes") === null);
            verify(findText(view, "Degraded sources: crt.sh, dns:dkim").visible);
            verify(findText(view, "Not compared: added_services, changed_confidence").visible);
            verify(findText(view, "Added Services: not compared").visible);
            compare(view.deltaCompletionMessage(view.deltaResult),
                "Baseline comparison incomplete (some fields not compared).");
        }

        function test_partial_with_comparable_changes() {
            view.deltaResult = {
                has_changes: true, added_services: ["Linear"], removed_services: [],
                incomplete_comparison: {
                    degraded_sources: ["dns:mx"], suppressed_fields: ["removed_services"]
                }
            };
            tryVerify(function() { return findText(view, "+ Linear") !== null; });
            var badge = findText(view, "Partial comparison");
            verify(badge !== null);
            verify(badge.visible);
            compare(badge.color.toString(), "#f9e2af");
            verify(findText(view, "+ Linear").visible);
            verify(findText(view, "Removed Services: not compared").visible);
            compare(view.deltaCompletionMessage(view.deltaResult),
                "Baseline comparison incomplete (changes observed in comparable fields).");
        }

        function test_complete_unchanged() {
            view.deltaResult = {has_changes: false, added_services: [], removed_services: [], incomplete_comparison: null};
            wait(0);
            var badge = findText(view, "No Changes");
            verify(badge !== null);
            verify(badge.visible);
            compare(badge.color.toString(), "#a6e3a1");
            compare(badge.parent.color.toString(), "#1e3a2f");
            compare(view.deltaCompletionMessage(view.deltaResult), "Baseline comparison complete (unchanged).");
        }

        function test_complete_changed() {
            view.deltaResult = {has_changes: true, added_services: ["Linear"], removed_services: ["Asana"], incomplete_comparison: null};
            tryVerify(function() { return findText(view, "+ Linear") !== null; });
            verify(findText(view, "- Asana") !== null);
            var badge = findText(view, "Changes Observed");
            verify(badge !== null);
            verify(badge.visible);
            compare(badge.color.toString(), "#f38ba8");
            compare(badge.parent.color.toString(), "#3e1f29");
            compare(view.deltaCompletionMessage(view.deltaResult), "Baseline comparison complete (changes observed).");
        }

        function test_suppressed_lists_are_not_rendered_as_observations() {
            view.deltaResult = {
                has_changes: true, added_services: ["Suppressed addition"], removed_services: ["Suppressed removal"],
                incomplete_comparison: {
                    degraded_sources: ["dns:mx"], suppressed_fields: ["added_services", "removed_services"]
                }
            };
            wait(0);
            verify(findText(view, "Added Services: not compared") !== null);
            verify(findText(view, "Removed Services: not compared") !== null);
            verify(findText(view, "+ Suppressed addition") === null);
            verify(findText(view, "- Suppressed removal") === null);
        }
    }
}
