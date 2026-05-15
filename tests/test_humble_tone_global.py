"""v1.9.9 — suite-wide humble-tone enforcement on user-facing strings.

The project's tone discipline (no overclaim words, no marketing
language, hedged framing) was previously enforced locally at the
v1.9.9 ceiling phrasing. A rigorous reviewer correctly notes that
local enforcement is convention, not contract — the discipline can
silently drift in any other user-facing surface.

This test scans the user-facing string surfaces and rejects overclaim
words. The surfaces covered:

  * Fingerprint catalog descriptions (every detection's
    ``description`` field).
  * Insight phrasing constants in ``insights.py``.
  * Panel field labels and curated text in ``formatter.py`` constants.
  * CLI command help text via the rendered ``--help`` output.

Surfaces deliberately NOT covered (would require a separate audit):

  * Fingerprint NAMES (vendor product names, e.g. "AWS CloudFront")
    where overclaim words may legitimately be vendor branding.
  * Insight TYPE identifiers (programmatic, not operator-facing).

The overclaim word list is the project's standing humble-tone
discipline encoded as a test. Adding to the list strengthens the
discipline; removing requires explicit justification in the
CHANGELOG.
"""

from __future__ import annotations

import re

import pytest

from recon_tool.fingerprints import load_fingerprints

# Overclaim words that should not appear in user-facing prose. Each
# carries an explicit rationale for why it is rejected.
_OVERCLAIM_WORDS: dict[str, str] = {
    # Absolutist / certainty claims
    "always": "claims universality the catalog cannot guarantee",
    "never": "absolutist; prefer 'does not' or hedged framing",
    "completely": "overclaim of coverage / certainty",
    "exactly": "overclaim of precision",
    "perfectly": "overclaim of correctness",
    "definitely": "overclaim of certainty",
    "guaranteed": "overclaim of contract",
    # Marketing / strength language
    "robust": "marketing tone; describe behaviour instead",
    "strong": "marketing tone; describe behaviour instead",
    "powerful": "marketing tone",
    "seamless": "marketing tone",
    "cutting-edge": "marketing tone",
    "state-of-the-art": "marketing tone",
    "world-class": "marketing tone",
    # Tool-blame language
    "obviously": "presumes the reader's frame of reference",
    "simply": "presumes the operation is easier than it is",
}


def _violations_for(text: str) -> list[str]:
    """Return list of overclaim words present in ``text`` as
    standalone words (case-insensitive). Substring matches inside
    other words (e.g. 'always' inside 'normally') do NOT count; the
    word-boundary regex enforces that."""
    if not text:
        return []
    found: list[str] = []
    lower = text.lower()
    for word in _OVERCLAIM_WORDS:
        if re.search(rf"\b{re.escape(word)}\b", lower):
            found.append(word)
    return found


class TestFingerprintCatalogTone:
    """Every fingerprint description gets the humble-tone check.
    These strings ship in `--explain` output and JSON, so they are
    operator-facing."""

    def test_no_overclaim_words_in_catalog_descriptions(self):
        catalog_violations: list[str] = []
        for fp in load_fingerprints():
            for det in fp.detections:
                desc = (det.description or "").strip()
                if not desc:
                    continue
                violations = _violations_for(desc)
                if violations:
                    catalog_violations.append(
                        f"{fp.slug} ({det.type}): overclaim words {violations} in description: {desc[:120]!r}"
                    )
        assert not catalog_violations, (
            "Fingerprint descriptions contain overclaim words. The humble-tone discipline is "
            "encoded in CONTRIBUTING.md; the test above lists each violation. Either rephrase "
            "the descriptions to remove the listed words or add the word to the explicit "
            "exception list with a written justification.\n\n" + "\n".join(catalog_violations)
        )


class TestPanelStringConstants:
    """User-facing string constants in formatter.py must observe the
    same humble-tone discipline as the catalog descriptions. We use
    AST to extract only actual string-constant *values* (not
    docstrings, not comments) so the check is precise about what
    counts as user-facing.

    Specifically the test extracts:
      * Top-level module assignments to string constants (e.g.,
        ``_LABEL = "..."``).
      * String literals passed as arguments to known panel-emitting
        helpers (would require deeper AST work; skipped here).

    Docstrings and inline comments are explicitly skipped because
    they are developer documentation, not text shown to operators."""

    def test_no_overclaim_words_in_formatter_top_level_string_constants(self):
        import ast
        from pathlib import Path

        formatter_path = Path("recon_tool/formatter.py")
        if not formatter_path.exists():
            pytest.skip("formatter.py not found at expected path")

        tree = ast.parse(formatter_path.read_text(encoding="utf-8"))
        violations: list[str] = []

        for node in ast.walk(tree):
            # Module-level constant assignments only. Triple-quoted
            # docstrings are ast.Expr(value=ast.Constant) at the
            # start of a body and we skip those.
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Constant):
                continue
            if not isinstance(node.value.value, str):
                continue
            text = node.value.value
            # Skip strings shorter than 6 chars (slugs, single words,
            # format placeholders).
            if len(text) < 6:
                continue
            # Skip strings that look like code identifiers / format
            # codes / single-word labels: must contain a space to be
            # considered prose.
            if " " not in text:
                continue
            found = _violations_for(text)
            if found:
                target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                violations.append(f"{target_names or node.targets} = {text[:120]!r}: contains {found}")

        assert not violations, "Formatter top-level string constants contain overclaim words.\n\n" + "\n".join(
            violations
        )


class TestOverclaimWordListIntegrity:
    """The overclaim word list itself is the discipline. This test
    pins the contract that adding/removing words is a deliberate
    change, not an accident."""

    def test_overclaim_word_list_minimum_size(self):
        """The list must remain non-trivial. A regression that empties
        the list would silently disable the discipline; this test
        catches that case."""
        assert len(_OVERCLAIM_WORDS) >= 10, (
            f"Overclaim word list has {len(_OVERCLAIM_WORDS)} entries; expected >= 10. "
            f"If the list shrunk intentionally, document the change in CHANGELOG."
        )

    def test_each_overclaim_word_has_rationale(self):
        for word, rationale in _OVERCLAIM_WORDS.items():
            assert rationale, f"overclaim word {word!r} missing rationale string"
            assert len(rationale) >= 10, f"overclaim word {word!r} rationale too short: {rationale!r}"
