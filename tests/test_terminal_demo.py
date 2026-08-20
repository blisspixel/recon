"""Contracts for the synthetic README terminal demonstration."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.generate_terminal_demo import (
    DEFAULT_OUTPUT,
    demo_tenant_info,
    main,
    render_terminal_demo_svg,
    render_terminal_demo_text,
)

ROOT = Path(__file__).resolve().parent.parent


def test_committed_terminal_demo_matches_the_real_renderer() -> None:
    svg = render_terminal_demo_svg()

    assert DEFAULT_OUTPUT == ROOT / "docs" / "assets" / "terminal-demo.svg"
    assert DEFAULT_OUTPUT.read_text(encoding="utf-8") == svg
    assert svg.startswith('<svg class="rich-terminal"')
    assert "Example&#160;Industries&#160;Ltd" in svg
    assert "Generated with Rich" not in svg
    assert "cdnjs.cloudflare.com" not in svg
    assert 'role="img"' in svg
    assert '<title id="recon-demo-accessible-title">' in svg
    assert '<desc id="recon-demo-accessible-description">' in svg
    assert "Example Industries" in svg
    assert demo_tenant_info().queried_domain == "example.com"
    assert main(["--check"]) == 0


def test_terminal_demo_width_is_independent_of_dumb_term(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")
    ordinary = render_terminal_demo_svg()

    monkeypatch.setenv("TERM", "dumb")
    noninteractive = render_terminal_demo_svg()

    assert noninteractive == ordinary
    assert 'viewBox="0 0 1019 757.5999999999999"' in noninteractive


def test_generator_check_mode_detects_drift(tmp_path: Path) -> None:
    output = tmp_path / "terminal-demo.svg"

    assert main(["--output", str(output)]) == 0
    assert main(["--output", str(output), "--check"]) == 0

    output.write_text("stale\n", encoding="utf-8")

    assert main(["--output", str(output), "--check"]) == 1

    output.write_bytes(render_terminal_demo_svg().replace("\n", "\r\n").encode("utf-8"))

    assert main(["--output", str(output), "--check"]) == 1


def test_readme_embeds_and_labels_the_synthetic_demo() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    normalized = " ".join(readme.split())
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()

    assert "https://raw.githubusercontent.com/blisspixel/recon/main/docs/assets/terminal-demo.svg" in readme
    assert "deterministic, no-network fixture" in normalized
    assert "Example Industries Ltd" in readme
    assert "No real organization is depicted" in normalized
    assert "<summary>Accessible text transcript</summary>" in readme
    assert render_terminal_demo_text() in readme

    # The illustration must never read as a capture of `recon example.com`.
    # recon ships no offline demo mode, so a reader who runs the Quick Start
    # command gets a live lookup of a reserved domain: sparse, and sometimes
    # carrying unrelated public residue. A README that implies otherwise sends
    # every new reader, and every agent following the front door, to narrate a
    # fixture the binary cannot produce.
    assert "Every lookup is live." in normalized
    assert "generated, not captured" in normalized
    assert "no live lookup of reserved" in normalized
    assert "README.md text eol=lf" in attributes
    assert "docs/assets/terminal-demo.svg text eol=lf" in attributes
