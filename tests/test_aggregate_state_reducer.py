"""Tests for the v2.1 downstream cohort reducer (validation/aggregate/).

The reducer is a sidecar, not recon core, so it is loaded by path. The per-cohort
math lives in recon_tool.cohort_summary (tested in test_cohort_summary.py); these
tests cover the downstream-only parts: weighted log-odds distinctiveness, caller
grouping, and the end-to-end honest behaviors on the synthetic fixture.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parent.parent
_AGG_DIR = _REPO / "validation" / "aggregate"
_spec = importlib.util.spec_from_file_location("aggregate_state_ref", _AGG_DIR / "aggregate_state.py")
assert _spec is not None
assert _spec.loader is not None
agg: Any = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agg)


def test_weighted_log_odds_flags_distinctive_term() -> None:
    group = {"proofpoint": 6, "common": 5}
    background = {"proofpoint": 0, "common": 30}
    scored = agg.weighted_log_odds(group, background)
    assert scored["proofpoint"][1] > scored["common"][1]  # higher z for the distinctive term


def _load_fixture() -> dict[str, Any]:
    records = agg.load_records(str(_AGG_DIR / "synthetic_cohort.ndjson"))
    grouping = agg.load_grouping(str(_AGG_DIR / "synthetic_groups.csv"))
    return agg.reduce_records(records, grouping)


def test_fixture_global_shape() -> None:
    summary = _load_fixture()
    assert summary["record_type"] == "cohort_summary"
    assert summary["global"]["n"] == 24
    assert summary["global"]["small_n_warning"] is True


def test_fixture_mnar_observability_below_one_for_hideable() -> None:
    m365 = _load_fixture()["global"]["prevalence"]["m365_tenant"]
    assert m365["observability_fraction"] < 1.0
    assert m365["lower_bound_over_cohort"] < m365["observed_rate"]


def test_fixture_declarative_never_sparse_hideable_can_be() -> None:
    claims = _load_fixture()["global"]["posterior_claims"]
    assert claims["email_security_policy_enforcing"]["sparse_share"] == 0.0
    assert claims["google_workspace_tenant"]["sparse_share"] > 0.0


def test_fixture_three_groups_with_distinctiveness() -> None:
    summary = _load_fixture()
    assert set(summary["by_group"]) == {"fintech", "healthcare", "saas"}
    assert "distinctiveness" in summary
    assert summary["by_group"]["fintech"]["mix"]["provider"]["hhi"] >= 0.5


def test_fixture_small_cell_suppression() -> None:
    fintech = _load_fixture()["by_group"]["fintech"]["prevalence"]["m365_tenant"]
    assert fintech["positives"] == "<=10 (suppressed)"


def test_distinctiveness_needs_two_groups() -> None:
    one = {"only": [{"slugs": ["a", "b"]}]}
    assert "note" in agg.distinctiveness(one)


def test_reducer_tolerates_malformed_records(tmp_path: Any) -> None:
    import json as _json

    bad = [
        42, "contoso.com", None,  # non-dict records, must be filtered
        {"queried_domain": "a.com", "provider": "Microsoft 365", "slugs": "proofpoint",
         "posterior_observations": 5, "degraded_sources": "dns"},  # non-list fields
    ]
    p = tmp_path / "bad.json"
    p.write_text(_json.dumps(bad), encoding="utf-8")
    recs = agg.load_records(str(p))
    assert all(isinstance(r, dict) for r in recs)  # non-dicts dropped
    summary = agg.reduce_records(recs)  # must not raise
    assert summary["global"]["n"] == 1


def test_reducer_skips_malformed_ndjson_line(tmp_path: Any) -> None:
    p = tmp_path / "bad.ndjson"
    p.write_text(
        '{"queried_domain":"a.com","provider":"Microsoft 365"}\n'
        "not valid json\n"
        '{"queried_domain":"b.com","provider":"Google Workspace"}\n',
        encoding="utf-8",
    )
    recs = agg.load_records(str(p))
    assert len(recs) == 2  # the malformed middle line is skipped, valid lines kept


def test_distinctiveness_total_order() -> None:
    # Each group's ranking must be in a total deterministic order (z desc, then
    # log-odds desc, then slug asc), not hash-seed-dependent set order.
    summary = _load_fixture()
    for rows in summary["distinctiveness"].values():
        keys = [(-r["z"], -r["log_odds"], r["slug"]) for r in rows]
        assert keys == sorted(keys)
