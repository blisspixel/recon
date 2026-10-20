"""Render ReconView.qml to an offscreen PNG image for visual inspection.

Pass ``--light`` to render the light fallback set instead of the dark one, and
``--output PATH`` to write somewhere other than the tracked preview image.
"""

import argparse
import os
import sys
from pathlib import Path

# Force offscreen QPA for headless rendering
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QUrl
from PySide6.QtGui import QFont, QFontDatabase, QGuiApplication
from PySide6.QtQuick import QQuickView

REPO_ROOT = Path(__file__).resolve().parents[1]
QML_FILE = REPO_ROOT / "integrations" / "omarchy" / "ReconView.qml"
OUTPUT_PNG = REPO_ROOT / "docs" / "assets" / "omarchy-recon-preview.png"


def render_preview(light: bool, output_png: Path) -> None:
    app = QGuiApplication(sys.argv[:1])

    # Load system font for offscreen rendering
    font_path = Path("C:/Windows/Fonts/segoeui.ttf")
    if font_path.is_file():
        font_id = QFontDatabase.addApplicationFont(str(font_path))
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families:
            app.setFont(QFont(families[0], 10))

    view = QQuickView()
    view.setResizeMode(QQuickView.ResizeMode.SizeViewToRootObject)
    view.setSource(QUrl.fromLocalFile(str(QML_FILE)))

    root_item = view.rootObject()
    if root_item is None:
        print("Error: Failed to load QML root object", file=sys.stderr)
        sys.exit(1)

    # Realistic mock lookup data matching recon --json output
    mock_lookup = {
        "queried_domain": "alpha.invalid",
        "display_name": "Synthetic Alpha Ltd",
        "provider": "Microsoft 365 + Proofpoint gateway",
        "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "confidence": "high",
        "email_security_score": 4,
        "ct_subdomain_count": 12,
        "services": [
            "Microsoft 365",
            "Proofpoint",
            "Okta",
            "Entra ID",
            "Cloudflare",
            "AWS Route 53",
            "Slack",
            "Atlassian",
        ],
        "insights": [
            "Federated identity observed; identity-vendor indicators: Okta",
            "Email security: observed controls: DMARC reject, DKIM, SPF strict, MTA-STS",
            "MX gateway observed: Proofpoint",
        ],
        "degraded_sources": [],
    }

    # Realistic mock delta data matching recon delta --json output
    mock_delta = {
        "has_changes": True,
        "added_services": ["Cloudflare CDN", "Slack Enterprise"],
        "removed_services": ["Legacy Mail Gateway"],
    }

    root_item.setProperty("lightTheme", light)
    root_item.setProperty("lookupResult", mock_lookup)
    root_item.setProperty("deltaResult", mock_delta)
    root_item.setProperty("activeDomain", "alpha.invalid")
    root_item.setProperty("statusMessage", "Lookup complete: 8 services observed.")

    view.show()
    app.processEvents()

    # Grab offscreen frame
    image = view.grabWindow()
    output_png.parent.mkdir(parents=True, exist_ok=True)
    if image.save(str(output_png)):
        print(f"Rendered QML preview successfully saved to {output_png}")
    else:
        print(f"Error: Failed to save image to {output_png}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--light", action="store_true", help="render the light fallback set")
    parser.add_argument("--output", type=Path, default=OUTPUT_PNG, help="PNG path to write")
    args = parser.parse_args()
    render_preview(args.light, args.output)
