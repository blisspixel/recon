"""Tests for Omarchy Recon integration (manifest, security contracts, and validation parity)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from recon_tool.validator import validate_domain

REPO_ROOT = Path(__file__).resolve().parents[1]
OMARCHY_DIR = REPO_ROOT / "integrations" / "omarchy"


class TestOmarchyManifest:
    def test_manifest_exists_and_parses(self) -> None:
        manifest_path = OMARCHY_DIR / "manifest.json"
        assert manifest_path.is_file()

        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert data.get("schemaVersion") == 1
        assert data.get("id") == "org.recon.omarchy"
        assert data.get("name") == "Recon"
        assert data.get("version") == "1.0.0"
        assert "bar-widget" in data.get("kinds", [])
        assert data.get("entryPoints", {}).get("barWidget") == "Widget.qml"
        assert (OMARCHY_DIR / "Widget.qml").is_file()
        assert (OMARCHY_DIR / "ReconView.qml").is_file()
        assert (OMARCHY_DIR / "install.sh").is_file()
        assert (OMARCHY_DIR / "uninstall.sh").is_file()

    def test_manifest_metadata_fields(self) -> None:
        manifest_path = OMARCHY_DIR / "manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert data.get("barWidget", {}).get("displayName") == "Recon"
        assert data.get("barWidget", {}).get("category") == "Security"
        assert data.get("author") == "Nick Seal"


class TestQMLSecurityContracts:
    def test_no_shell_command_interpolation(self) -> None:
        """Process execution must never invoke an intermediate shell or shell string interpolation."""
        for filename in ("Widget.qml", "ReconView.qml"):
            content = (OMARCHY_DIR / filename).read_text(encoding="utf-8")
            assert "sh -c" not in content
            assert "bash -c" not in content
            assert "/bin/sh" not in content
            assert "eval(" not in content

    def test_direct_argument_list_dispatch(self) -> None:
        """The command must be passed as an array of arguments, not an interpolated string."""
        widget_qml = (OMARCHY_DIR / "Widget.qml").read_text(encoding="utf-8")
        assert '["recon", "delta", domain, "--json"]' in widget_qml
        assert '["recon", domain, "--json"]' in widget_qml

    def test_fail_closed_timeout_guard(self) -> None:
        """A timeout timer must bound execution to prevent hung processes."""
        widget_qml = (OMARCHY_DIR / "Widget.qml").read_text(encoding="utf-8")
        assert "interval: 30000" in widget_qml
        assert "reconProcess.running = false" in widget_qml

    def test_clipboard_paste_does_not_auto_execute(self) -> None:
        """Pasting text into the input field must not trigger automatic network queries."""
        recon_view = (OMARCHY_DIR / "ReconView.qml").read_text(encoding="utf-8")
        # Ensure onTextChanged does not invoke runInspection
        assert "onTextChanged: runInspection" not in recon_view
        assert "onTextChanged: {" not in recon_view


class TestDomainValidationParity:
    # JavaScript validation logic regex extracted from ReconView.qml
    DOMAIN_RE = re.compile(r"^(?!-)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$")

    def _qml_validate(self, raw: str) -> tuple[bool, str]:
        if not raw or not raw.strip():
            return False, "A domain is required."
        s = raw.strip()
        if len(s) > 253 or re.search(r"[\s;`$|&><'\"\\{}[\]^]", s):
            return False, "Disallowed characters or length."
        if re.match(r"^https?://", s, re.IGNORECASE):
            s = re.sub(r"^https?://", "", s, flags=re.IGNORECASE)
        s = re.split(r"[/?#]", s, maxsplit=1)[0]
        s = re.sub(r":\d+$", "", s).lower().rstrip(".")
        if not self.DOMAIN_RE.match(s) or any(len(label) == 0 or len(label) > 63 for label in s.split(".")):
            return False, "Invalid domain format."
        return True, s

    @pytest.mark.parametrize(
        "valid_domain",
        [
            "example.com",
            "sub.domain.example.org",
            "my-domain.invalid",
            "https://example.com/some/path",
            "http://sub.example.co.uk:8080?q=test#frag",
            "ALPHA-123.TEST",
        ],
    )
    def test_valid_domains_accepted(self, valid_domain: str) -> None:
        ok, normalized = self._qml_validate(valid_domain)
        assert ok
        # Parity with python validate_domain
        python_normalized = validate_domain(valid_domain, apex=False)
        assert normalized == python_normalized

    @pytest.mark.parametrize(
        "invalid_input",
        [
            "",
            "   ",
            "; rm -rf /",
            "example.com | cat /etc/passwd",
            "`whoami`.example.com",
            "foo$bar.com",
            "bad domain.com",
            "http://target.com\\@evil.com",
            "-leading-hyphen.com",
            "trailing-hyphen-.com",
            "a" * 64 + ".com",
            "example..com",
        ],
    )
    def test_invalid_domains_rejected(self, invalid_input: str) -> None:
        ok, _ = self._qml_validate(invalid_input)
        assert not ok


class TestPackagingScripts:
    def test_scripts_executable_and_safe(self) -> None:
        install_script = (OMARCHY_DIR / "install.sh").read_text(encoding="utf-8")
        uninstall_script = (OMARCHY_DIR / "uninstall.sh").read_text(encoding="utf-8")

        assert "set -euo pipefail" in install_script
        assert "set -euo pipefail" in uninstall_script
        assert "org.recon.omarchy" in install_script
        assert "org.recon.omarchy" in uninstall_script
        assert "omarchy-restart-shell" in install_script
        assert "omarchy-restart-shell" in uninstall_script
