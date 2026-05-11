"""v1.9.3.6 — validation harness path-containment regression tests.

Pins the input-validation hardening in
``validation.agentic_ux.run._load_persona`` /
``_load_fixture``: persona and fixture selectors must match a strict
identifier shape, and the resolved path must stay under the intended
directory.

The audit finding (informational) flagged that ``--personas`` and
``--fixtures`` CLI values were interpolated directly into ``Path``
objects without rejecting traversal, absolute paths, or separators.
The harness then read the resulting file and embedded its contents
in a prompt sent to a configured LLM provider — turning a
maintainer-only tool into a local-file-exfiltration sink when run
with hostile arguments.

This patch is defense-in-depth (the affected code is dev-only and
not packaged in the wheel) but the audit was correct to call it
out: a future maintainer adding a CI wrapper or letting an agent
choose persona names would inherit the gap unless the harness
itself rejected unsafe selectors.
"""

from __future__ import annotations

import pytest

from validation.agentic_ux.run import (
    _SAFE_NAME_RE,
    _load_fixture,
    _load_persona,
    _validate_name,
)

# ── Format validation ──────────────────────────────────────────────


class TestValidateName:
    """``_validate_name`` accepts in-repo names and rejects everything
    else."""

    @pytest.mark.parametrize(
        "name",
        [
            "analyst",
            "researcher",
            "ops",
            "contoso-dense",
            "hardened-sparse",
            "a",
            "Z",
            "name_with_underscore",
            "name-with-hyphens",
            "name123",
            "1leading-digit",
            "a" * 64,  # max length
        ],
    )
    def test_accepts_legitimate_names(self, name):
        assert _validate_name("persona", name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "../etc/passwd",
            "..",
            "../../secrets",
            "/etc/passwd",
            "/absolute/path",
            "\\windows\\path",
            "with space",
            "with.dot",
            "with/slash",
            "with\\backslash",
            "-leading-dash",
            "_leading-underscore",
            ".hidden",
            "name\x00null",
            "a" * 65,  # over max length
        ],
    )
    def test_rejects_unsafe_names(self, name):
        with pytest.raises(ValueError, match="not a safe identifier"):
            _validate_name("persona", name)

    def test_safe_name_regex_anchored(self):
        # The regex must be anchored — otherwise "../valid" would
        # match because "valid" appears at the end.
        assert _SAFE_NAME_RE.pattern.startswith("^")
        assert _SAFE_NAME_RE.pattern.endswith("$")


# ── Loader path containment ────────────────────────────────────────


class TestLoaderRejectsUnsafePaths:
    """``_load_persona`` and ``_load_fixture`` raise on unsafe names
    before any filesystem read."""

    @pytest.mark.parametrize(
        "name",
        [
            "../etc/passwd",
            "../../secrets",
            "/etc/passwd",
            "with/slash",
            "with space",
            "..",
            "",
        ],
    )
    def test_load_persona_rejects(self, name):
        with pytest.raises(ValueError, match="not a safe identifier"):
            _load_persona(name)

    @pytest.mark.parametrize(
        "name",
        [
            "../etc/passwd",
            "../../secrets",
            "/etc/passwd",
            "with/slash",
            "with space",
            "..",
            "",
        ],
    )
    def test_load_fixture_rejects(self, name):
        with pytest.raises(ValueError, match="not a safe identifier"):
            _load_fixture(name)


# ── Legitimate names still load ────────────────────────────────────


class TestLegitimateLoaders:
    """Sanity check: the in-repo persona/fixture names still load
    cleanly after the validation hardening."""

    @pytest.mark.parametrize("name", ["analyst", "researcher", "ops"])
    def test_existing_personas_load(self, name):
        body = _load_persona(name)
        assert isinstance(body, str)
        assert body  # non-empty

    @pytest.mark.parametrize("name", ["contoso-dense", "hardened-sparse"])
    def test_existing_fixtures_load(self, name):
        payload = _load_fixture(name)
        assert isinstance(payload, dict)
        assert payload  # non-empty
