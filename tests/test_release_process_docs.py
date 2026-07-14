from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_release_process_docs_include_supply_chain_recipe_guard() -> None:
    text = _normalized(ROOT / "docs" / "release-process.md")

    for required in (
        "supply-chain consumer-verification recipe",
        "README usage anchors, supply-chain recipe anchors, and repository hygiene",
        "docs/supply-chain.md",
        "consumer verification quick path",
        "current version and release asset names",
    ):
        assert required in text


def test_reviewer_and_loop_docs_name_supply_chain_recipe_freshness() -> None:
    for path in (
        ROOT / "docs" / "artifact-review.md",
        ROOT / "docs" / "agentic-balance.md",
    ):
        assert "supply-chain recipe freshness" in _normalized(path), path


def test_release_yank_guidance_uses_supported_pypi_flow() -> None:
    text = _normalized(ROOT / "docs" / "release-process.md")

    assert "Twine does not provide a yank command" in text
    assert "PyPI project management UI" in text
    assert "twine yank" not in text
