"""v1.9.9 — differential agreement: three independent trigger
implementations.

The corpus aggregator and the renderer are both authored by the same
person. If both have the same bug, both pass and we ship. The
mitigation is a *third* independent implementation that reaches the
same fired/suppressed verdict via a different code path — a regex
parser of the rendered text. If all three agree on the same set of
TenantInfo fixtures, the trigger logic is well-specified independent
of any one implementation.

The three implementations under test:

  1. **Renderer** (`render_tenant_panel` in formatter.py): the panel
     renders the surfaces inline via the trigger code we want to
     pin.
  2. **Aggregator** (`_multi_cloud_fired`, `_ceiling_fired` in
     corpus_aggregator.py): mirrors the renderer's trigger logic for
     fast scoring across a corpus.
  3. **Regex parser** (in this file): looks at the rendered text
     output and matches the panel-line shape that indicates the
     surface fired. Has no shared code with implementations 1 or 2.

If all three agree on every fixture, the trigger contract is
load-bearing across implementations. If they disagree, at least one
implementation has a bug — and the disagreement points at it.
"""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

from rich.console import Console

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.cache import tenant_info_from_dict
from recon_tool.formatter import render_tenant_panel
from validation.corpus_aggregator import (
    _ceiling_fired,
    _estimate_categorized_count,
    _multi_cloud_fired,
)

# ── Implementation 3: regex parser ─────────────────────────────────────
# These regexes are deliberately narrow on purpose. They match the
# specific panel shape v1.9.9 produces; a future renderer change that
# reshapes the line would surface as a regex miss, and the differential
# test would flag the disagreement at PR time.

_MULTI_CLOUD_LINE = re.compile(r"Multi-cloud\s+\d+ providers observed \([^)]+\)")
_CEILING_HEADER = re.compile(r"Passive-DNS ceiling\b")


def _render(info) -> str:
    console = Console(no_color=True, record=True, width=120, file=io.StringIO())
    rendered = render_tenant_panel(info)
    console.print(rendered)
    return console.export_text()


def _regex_multi_cloud_fired(rendered: str) -> bool:
    return bool(_MULTI_CLOUD_LINE.search(rendered))


def _regex_ceiling_fired(rendered: str) -> bool:
    return bool(_CEILING_HEADER.search(rendered))


def _all_synthetic_fixtures() -> list[dict]:
    fixture_dir = REPO_ROOT / "validation" / "synthetic_corpus" / "fixtures"
    if not fixture_dir.exists():
        return []
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(fixture_dir.glob("*.json"))]


class TestThreeImplementationAgreement:
    """The strongest invariant: for every fixture, the three trigger
    implementations agree on whether each surface fires. Any
    disagreement is a bug in at least one of them and pinpoints the
    one to investigate."""

    def test_multi_cloud_three_way_agreement_across_corpus(self):
        fixtures = _all_synthetic_fixtures()
        assert fixtures, "synthetic corpus fixtures missing; run validation/synthetic_corpus/generator.py"

        disagreements: list[str] = []
        for entry in fixtures:
            info = tenant_info_from_dict(entry)
            rendered = _render(info)

            agg_fired, _ = _multi_cloud_fired(info)
            regex_fired = _regex_multi_cloud_fired(rendered)
            renderer_fired = "Multi-cloud" in rendered

            if not (agg_fired == regex_fired == renderer_fired):
                disagreements.append(
                    f"{info.queried_domain}: aggregator={agg_fired}, regex={regex_fired}, renderer={renderer_fired}"
                )

        assert not disagreements, (
            "Three-way trigger disagreement on multi-cloud rollup. "
            "If the aggregator and renderer agree but the regex disagrees, "
            "the regex is too narrow (or the panel-line shape changed without updating the regex). "
            "If the aggregator disagrees with the other two, the aggregator's "
            "trigger logic has drifted from the renderer. Disagreements:\n  " + "\n  ".join(disagreements)
        )

    def test_ceiling_three_way_agreement_across_corpus(self):
        fixtures = _all_synthetic_fixtures()
        assert fixtures, "synthetic corpus fixtures missing; run validation/synthetic_corpus/generator.py"

        disagreements: list[str] = []
        for entry in fixtures:
            info = tenant_info_from_dict(entry)
            rendered = _render(info)

            cat_count = _estimate_categorized_count(info)
            agg_fired = _ceiling_fired(info, cat_count)
            regex_fired = _regex_ceiling_fired(rendered)
            renderer_fired = "Passive-DNS ceiling" in rendered

            # Note on the agg-vs-renderer expected gap: the aggregator
            # uses a slug-only lower bound for the categorized count
            # while the renderer uses both slug and pass-2 prefix
            # classification. The aggregator can over-fire on fixtures
            # where pass-2 lifts the categorized count above the
            # threshold. We test renderer-vs-regex strictly (these
            # MUST agree) and aggregator-vs-renderer with a known
            # over-count tolerance.
            if regex_fired != renderer_fired:
                disagreements.append(
                    f"{info.queried_domain}: regex={regex_fired} != renderer={renderer_fired} "
                    f"(regex is the test of the regex itself)"
                )

            # The aggregator may over-fire (produce True where the
            # renderer is False) but must NEVER under-fire (False where
            # renderer is True). Under-firing would mean the
            # aggregator misses cases the panel actually shows the
            # operator.
            if renderer_fired and not agg_fired:
                disagreements.append(
                    f"{info.queried_domain}: aggregator UNDER-fires — renderer shows ceiling, aggregator does not"
                )

        assert not disagreements, (
            "Trigger disagreement on ceiling. The renderer-vs-regex check "
            "is strict (any disagreement is a renderer or regex bug); the "
            "renderer-vs-aggregator check tolerates the aggregator's known "
            "over-firing but flags any under-firing. Disagreements:\n  " + "\n  ".join(disagreements)
        )


class TestRegexImplementationIsIndependent:
    """Sanity that the regex implementation is genuinely independent
    of the renderer's trigger code: grepping a string for a pattern
    must not import or call any trigger logic."""

    def test_regex_multi_cloud_fires_on_constructed_string(self):
        """The regex matches a synthetic multi-cloud line without
        invoking the renderer. Confirms it is a string-only check."""
        synthetic_panel = "  Multi-cloud  3 providers observed (AWS, Cloudflare, GCP)\n"
        assert _regex_multi_cloud_fired(synthetic_panel) is True

    def test_regex_multi_cloud_suppresses_on_unrelated_string(self):
        """The regex must not false-positive on text that mentions
        cloud vendors but is not a Multi-cloud panel line."""
        unrelated = "AWS CloudFront and GCP Compute Engine are both cloud vendors.\n"
        assert _regex_multi_cloud_fired(unrelated) is False

    def test_regex_ceiling_fires_on_constructed_string(self):
        synthetic_panel = "Passive-DNS ceiling\n  Passive DNS surfaces what publishes externally.\n"
        assert _regex_ceiling_fired(synthetic_panel) is True

    def test_regex_ceiling_suppresses_on_unrelated_string(self):
        unrelated = "The passive DNS layer hits a ceiling on hardened targets.\n"
        # Lowercase 'passive dns' should not match the bold-cased panel header.
        assert _regex_ceiling_fired(unrelated) is False
