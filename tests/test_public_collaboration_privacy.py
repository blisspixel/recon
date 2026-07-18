from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_fingerprint_pr_template_does_not_solicit_target_data() -> None:
    text = _read(".github/PULL_REQUEST_TEMPLATE/fingerprint.md")

    assert "## Test domain" not in text
    assert "known to use this service" not in text
    assert "Do not include" in text
    assert "Reserved positive fixture" in text
    assert "no evaluated-target identity" in text


def test_public_issue_forms_require_synthetic_reproductions() -> None:
    bug = _read(".github/ISSUE_TEMPLATE/bug_report.yml")
    fingerprint = _read(".github/ISSUE_TEMPLATE/fingerprint_request.yml")

    assert "explicit synthetic identity under `.invalid` or `.test`" in bug
    assert "Public-data acknowledgement" in bug
    assert "Public-data acknowledgement" in fingerprint
    assert "Do not paste an observed target-owned record" in fingerprint


def test_fingerprint_guidance_keeps_live_targets_private() -> None:
    text = _read("docs/fingerprints.md")

    assert "minimal reserved synthetic fixture" in text
    assert "validation/corpus-private/" in text
    assert "never the real domain list or per-domain output" in text


def test_examples_explain_the_reserved_target_boundary() -> None:
    text = _read("examples/README.md")

    assert "RFC 2606" in text
    assert "Target domains use `.invalid`" in text
    assert "detection definitions, not evaluated targets" in text
