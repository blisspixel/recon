from __future__ import annotations

import json

from validation.find_gaps import find_gaps


def test_find_gaps_counts_distinct_namespaces_without_emitting_their_list(tmp_path) -> None:
    payload = [
        {
            "queried_domain": "first.example",
            "unclassified_cname_chains": [
                {"subdomain": "one.first.example", "chain": ["a.edge.vendor.test"]},
                {"subdomain": "two.first.example", "chain": ["b.edge.vendor.test"]},
            ],
        },
        {
            "queried_domain": "second.example",
            "unclassified_cname_chains": [
                {"subdomain": "one.second.example", "chain": ["c.edge.vendor.test"]},
            ],
        },
        {
            "queried_domain": "FIRST.EXAMPLE",
            "unclassified_cname_chains": [
                {"subdomain": "three.first.example", "chain": ["d.edge.vendor.test"]},
            ],
        },
    ]
    source = tmp_path / "results.json"
    source.write_text(json.dumps(payload), encoding="utf-8")

    rows = find_gaps(source)

    assert rows[0]["count"] == 4
    assert rows[0]["distinct_namespace_count"] == 2
    assert set(rows[0]) == {"suffix", "count", "distinct_namespace_count", "samples"}
    assert "first.example" not in rows[0]
