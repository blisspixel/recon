from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
FIGURE_DOC = ROOT / "docs" / "paper-figures.md"
ASSET_DIR = ROOT / "docs" / "assets" / "paper"
GENERATOR = ROOT / "scripts" / "generate_paper_figures.py"
DOMAIN_TOKEN_RE = re.compile(r"(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+\b")


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_paper_figures", GENERATOR)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_paper_figure_assets_match_generator() -> None:
    generator = _load_generator()
    expected = generator.build_assets()

    assert set(expected) == {
        "assurance-architecture.svg",
        "bayesian-dag.svg",
        "calibration-reliability.svg",
        "interval-width-vs-evidence.svg",
    }
    for name, content in expected.items():
        path = ASSET_DIR / name
        assert path.read_text(encoding="utf-8") == content
        assert "<svg" in content
        assert "role=\"img\"" in content


def test_paper_figure_package_is_linked_from_research_docs() -> None:
    for path in (
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "external-writeup-plan.md",
        ROOT / "docs" / "artifact-review.md",
        ROOT / "docs" / "paper-outline.md",
        ROOT / "docs" / "paper-draft.md",
    ):
        assert "paper-figures.md" in path.read_text(encoding="utf-8")


def test_paper_figure_doc_names_assets_and_regeneration_gate() -> None:
    text = FIGURE_DOC.read_text(encoding="utf-8")

    for required in (
        "scripts/generate_paper_figures.py --check",
        "assets/paper/assurance-architecture.svg",
        "assets/paper/bayesian-dag.svg",
        "assets/paper/calibration-reliability.svg",
        "assets/paper/interval-width-vs-evidence.svg",
        "target domains",
        "per-domain rows",
    ):
        assert required in text


def test_band_figure_uses_current_uncertainty_semantics() -> None:
    generator = _load_generator()
    figure = generator.render_interval_width()
    documentation = FIGURE_DOC.read_text(encoding="utf-8")

    for stale_claim in (
        "Interval width falls as effective evidence rises",
        "Effective evidence bucket",
        "Mean 80% interval width",
    ):
        assert stale_claim not in figure
        assert stale_claim not in documentation

    for required in (
        "Observed band width by display-mass bucket",
        "Effective display-mass bucket",
        "Mean 80% uncertainty-band width",
        "no monotonicity or coverage claim",
    ):
        assert required in figure

    assert "not a general monotonicity result" in documentation
    assert "effective sample size" in documentation


def test_reliability_figure_names_its_dependency_boundary() -> None:
    generator = _load_generator()
    figure = generator.render_calibration_reliability()
    documentation = FIGURE_DOC.read_text(encoding="utf-8")

    assert "Dependency-qualified, not independent calibration" in figure
    assert "not independent calibration" in documentation


def test_svg_assets_do_not_contain_target_identifiers() -> None:
    allowed_domains = {"w3.org", "www.w3.org"}
    forbidden_fragments = ("tenant_id", "tenant ID")

    for path in ASSET_DIR.glob("*.svg"):
        text = path.read_text(encoding="utf-8")
        observed_domains = {match.group(0).lower() for match in DOMAIN_TOKEN_RE.finditer(text)}
        assert observed_domains <= allowed_domains
        for fragment in forbidden_fragments:
            assert fragment not in text


def test_paper_draft_figure_open_items_are_closed() -> None:
    text = (ROOT / "docs" / "paper-draft.md").read_text(encoding="utf-8")
    compact = " ".join(text.split())

    assert "Engine follow-up: decide whether private-corpus calibration rows need" not in text
    assert "Figures: architecture diagram" not in text
    assert "Done in the figure pass" in compact
