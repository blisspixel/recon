"""Aggregate panel-surface firings (Multi-cloud, ceiling) across a corpus.

This script consumes a ``results.json`` produced by ``validation/scan.py``
(or the equivalent ``recon batch --json`` output) and emits aggregated
statistics on whether the v1.9.9-and-later panel surfaces fire across
the corpus. Introduced in v1.9.9; designed to remain useful for future
panel-derivation analyses without renaming.

The output is **aggregate counts only**, never per-domain names: the
script is committed to the public repo but its inputs come from the
gitignored ``validation/corpus-private/`` corpus. The aggregated output
is safe to commit (it is, by construction, anonymized).

Output shape::

    {
      "corpus_size": 91,
      "multi_cloud": {
        "fired": 47,
        "suppressed": 44,
        "fired_share": 0.516,
        "vendor_count_distribution": {"2": 31, "3": 12, "4": 4}
      },
      "ceiling": {
        "fired": 6,
        "suppressed": 85,
        "fired_share": 0.066,
        "fired_with_zero_attribs": 6,
        "fired_with_one_to_four_attribs": 0
      },
      "wordlist_breadth": {
        "subdomain_count_mean": 14.2,
        "subdomain_count_median": 11,
        "subdomain_count_max": 73
      }
    }

Usage::

    python validation/corpus_aggregator.py \\
        validation/runs-private/2026-05-14T...Z/results.json \\
        --output validation/runs-private/2026-05-14T...Z/aggregate.json

The runner does not write any per-domain detail to disk. It also does
not need network access: all rendering and trigger checking happens
against the already-collected JSON data.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from rich.console import Console  # noqa: E402

from recon_tool.cache import tenant_info_from_dict  # noqa: E402
from recon_tool.formatter import (  # noqa: E402
    canonical_cloud_vendor,
    category_for_slug,
    render_tenant_panel,
)


def _surface_slug_stream(info: Any) -> list[str]:
    out: list[str] = []
    for sa in info.surface_attributions:
        if sa.primary_slug:
            out.append(sa.primary_slug)
        if sa.infra_slug:
            out.append(sa.infra_slug)
    return out


def _multi_cloud_fired(info: Any) -> tuple[bool, int]:
    """Return ``(fired, distinct_vendor_count)``.

    Mirrors the trigger logic in ``render_tenant_panel``: canonicalize
    apex slugs and surface-attribution slugs together; count distinct
    vendors; fire when ``>= 2``.
    """
    vendors: set[str] = set()
    for slug in (*info.slugs, *_surface_slug_stream(info)):
        v = canonical_cloud_vendor(slug)
        if v is not None:
            vendors.add(v)
    return (len(vendors) >= 2, len(vendors))


def _ceiling_fired(info: Any, categorized_count: int) -> bool:
    """Return whether the ceiling footer would fire.

    Mirrors the trigger logic in ``render_tenant_panel``: requires
    services non-empty, domain_count >= 3, categorized_count < 5,
    surface_attributions count < 5.
    """
    return (
        bool(info.services) and info.domain_count >= 3 and categorized_count < 5 and len(info.surface_attributions) < 5
    )


def _estimate_categorized_count(info: Any) -> int:
    """Rough proxy for the count of distinct service categories.

    Uses ``category_for_slug`` (a public accessor over the panel's
    category-by-slug map) without re-running the full pass-2 prefix
    classifier. This is a *lower bound* on the true categorized count
    and slightly under-estimates for fixtures whose raw service strings
    file under additional categories via pass 2. For corpus-aggregate
    purposes the lower bound is fine; the script flags this in its
    output so readers understand the precision limit.
    """
    cats: set[str] = set()
    for slug in info.slugs:
        cat = category_for_slug(slug)
        if cat:
            cats.add(cat)
    return len(cats)


def _render_to_string(info: Any) -> str:
    """Render the panel and capture as plain text, mirroring how the
    tests do it. Used for end-to-end firing detection rather than the
    estimator-based lower-bound check.

    Routes the Rich Console output to an in-memory ``StringIO`` rather
    than the real terminal. Tests run under pytest's stdout capture,
    so the test renderer pattern works in test context; the aggregator
    runs from a normal Python invocation and would otherwise attempt
    to write Rich box characters to a Windows cp1252 terminal, which
    crashes on the unicode rule line.
    """
    import io

    console = Console(no_color=True, record=True, width=120, file=io.StringIO())
    rendered = render_tenant_panel(info)
    console.print(rendered)
    return console.export_text()


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    multi_cloud_fired = 0
    vendor_counts: list[int] = []
    ceiling_fired = 0
    ceiling_zero_attribs = 0
    multi_cloud_rendered = 0  # Confirmed via end-to-end render
    ceiling_rendered = 0  # Confirmed via end-to-end render
    subdomain_counts: list[int] = []

    corpus_size = len(results)
    skipped = 0

    for entry in results:
        try:
            info = tenant_info_from_dict(entry)
        except Exception:
            skipped += 1
            continue

        # Estimator-based check (fast, lower bound on categorized count)
        fired_mc, vendor_count = _multi_cloud_fired(info)
        if fired_mc:
            multi_cloud_fired += 1
            vendor_counts.append(vendor_count)

        cat_count = _estimate_categorized_count(info)
        if _ceiling_fired(info, cat_count):
            ceiling_fired += 1
            if len(info.surface_attributions) == 0:
                ceiling_zero_attribs += 1

        # End-to-end render check. Authoritative: matches what an
        # operator actually sees in the panel. Slower but precise.
        # Render failures are skipped (the panel layer is otherwise
        # well-tested for resilience by ``test_adversarial_render.py``;
        # an exception here is a per-fixture anomaly, not a corpus-
        # wide signal).
        try:
            rendered = _render_to_string(info)
            if "Multi-cloud" in rendered:
                multi_cloud_rendered += 1
            if "Passive-DNS ceiling" in rendered:
                ceiling_rendered += 1
        except Exception:  # noqa: S110 — per-fixture anomaly, see comment above.
            pass

        subdomain_counts.append(len(info.related_domains))

    counted = corpus_size - skipped

    def _share(numer: int, denom: int) -> float:
        return round(numer / denom, 3) if denom else 0.0

    vendor_distribution: dict[str, int] = {}
    for count in vendor_counts:
        key = str(count)
        vendor_distribution[key] = vendor_distribution.get(key, 0) + 1

    return {
        "corpus_size": corpus_size,
        "counted": counted,
        "skipped_load_errors": skipped,
        "multi_cloud": {
            "fired": multi_cloud_fired,
            "suppressed": counted - multi_cloud_fired,
            "fired_share": _share(multi_cloud_fired, counted),
            "vendor_count_distribution": vendor_distribution,
            "rendered_fired": multi_cloud_rendered,
            "rendered_fired_share": _share(multi_cloud_rendered, counted),
        },
        "ceiling": {
            "fired": ceiling_fired,
            "suppressed": counted - ceiling_fired,
            "fired_share": _share(ceiling_fired, counted),
            "fired_with_zero_attribs": ceiling_zero_attribs,
            "rendered_fired": ceiling_rendered,
            "rendered_fired_share": _share(ceiling_rendered, counted),
        },
        "wordlist_breadth_proxy": {
            "subdomain_count_mean": (round(statistics.mean(subdomain_counts), 1) if subdomain_counts else 0.0),
            "subdomain_count_median": (int(statistics.median(subdomain_counts)) if subdomain_counts else 0),
            "subdomain_count_max": max(subdomain_counts) if subdomain_counts else 0,
        },
        "_notes": [
            (
                "Both an estimator-based and a render-based firing count are reported. "
                "The estimator (``fired`` / ``fired_share``) uses a slug-only lower-bound on the "
                "categorized count and therefore over-fires the ceiling vs reality. "
                "The render-based number (``rendered_fired`` / ``rendered_fired_share``) "
                "drives the actual panel and is the authoritative measurement."
            ),
            (
                "subdomain_count is a proxy for wordlist-breadth gains; "
                "per-prefix-class breakdown requires a richer instrumentation pass."
            ),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate v1.9.9 panel-surface firings across a recon batch results.json"
    )
    parser.add_argument("results_path", type=Path, help="Path to a recon batch results.json")
    parser.add_argument("--output", type=Path, help="Where to write the aggregate JSON; stdout if omitted")
    args = parser.parse_args(argv)

    raw = json.loads(args.results_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "results" in raw:
        results = raw["results"]
    elif isinstance(raw, list):
        results = raw
    else:
        msg = f"unexpected results.json shape: {type(raw)}"
        raise SystemExit(msg)

    agg = aggregate(results)
    out_text = json.dumps(agg, indent=2)

    if args.output:
        args.output.write_text(out_text + "\n", encoding="utf-8")
    else:
        print(out_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
