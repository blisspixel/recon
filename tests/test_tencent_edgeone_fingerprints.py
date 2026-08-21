"""Evidence and precision boundaries for reviewed Tencent EdgeOne rules."""

from __future__ import annotations

import pytest

from recon_tool.fingerprints import get_cname_target_rules, load_fingerprints
from recon_tool.sources.dns import _classify_chain


def _edgeone_rule(pattern: str):
    matches = [
        rule
        for fingerprint in load_fingerprints()
        if fingerprint.slug == "tencent-edgeone"
        for rule in fingerprint.detections
        if rule.type == "cname_target" and rule.pattern == pattern
    ]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize(
    ("pattern", "reference"),
    [
        ("eo.dnse0.com", "https://www.tencentcloud.com/document/product/1145/56175"),
        ("eo.dnse2.com", "https://www.tencentcloud.com/document/product/1145/67541"),
        ("eo.dnse3.com", "https://www.tencentcloud.com/document/product/1145/54132"),
        ("eo.dnse5.com", "https://www.tencentcloud.com/document/product/1145/59024"),
    ],
)
def test_current_edgeone_shards_have_exact_scoped_evidence(
    pattern: str,
    reference: str,
) -> None:
    rule = _edgeone_rule(pattern)

    assert rule.reference == reference
    assert rule.verified == "2026-08-21"
    assert "does not establish active traffic" in rule.description


@pytest.mark.parametrize("pattern", ["eo.dnse1.com", "eo.dnse4.com"])
def test_unsupported_edgeone_shards_remain_undated(pattern: str) -> None:
    rule = _edgeone_rule(pattern)

    assert rule.reference == ""
    assert rule.verified == ""
    assert "undated" in rule.description.lower()
    assert "current" in rule.description.lower()


@pytest.mark.parametrize("shard", range(6))
def test_edgeone_shards_are_label_bounded(shard: int) -> None:
    rules = get_cname_target_rules()
    pattern = f"eo.dnse{shard}.com"

    application, infrastructure = _classify_chain(
        [f"synthetic.example.{pattern}"],
        rules,
    )
    lookalike_application, lookalike_infrastructure = _classify_chain(
        [f"synthetic.example.{pattern}.example.net"],
        rules,
    )

    assert application is None
    assert infrastructure is not None
    assert infrastructure.slug == "tencent-edgeone"
    assert infrastructure.pattern == pattern
    assert lookalike_application is None
    assert lookalike_infrastructure is None
