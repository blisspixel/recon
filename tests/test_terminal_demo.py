"""Contracts for the synthetic README terminal demonstration."""

from __future__ import annotations

from pathlib import Path

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
    assert "example.com" in svg
    assert "Generated with Rich" not in svg
    assert "cdnjs.cloudflare.com" not in svg
    assert 'role="img"' in svg
    assert '<title id="recon-demo-accessible-title">' in svg
    assert '<desc id="recon-demo-accessible-description">' in svg
    assert "Example Industries" in svg
    assert demo_tenant_info().queried_domain == "example.com"
    assert main(["--check"]) == 0


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
    assert "example.com" in readme
    assert "No real organization is depicted" in normalized
    assert "<summary>Accessible text transcript</summary>" in readme
    assert render_terminal_demo_text() in readme
    assert "README.md text eol=lf" in attributes
    assert "docs/assets/terminal-demo.svg text eol=lf" in attributes
