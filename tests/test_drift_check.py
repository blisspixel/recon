"""PV2 inference drift gate.

``validation/drift_check.py`` fingerprints the Bayesian network's CPT-implied
marginals (no corpus, deterministic) and compares them to the committed
``validation/inference_baseline.json``. The first test below IS the CI gate: an
edit to ``bayesian_network.yaml`` that shifts an implied distribution beyond the
band fails here until the baseline is regenerated with
``python -m validation.drift_check --update`` and committed, which surfaces the
shift in the diff for review (the CPT-change discipline). The remaining tests
prove the comparison actually catches a material move and ignores sub-band noise.

The baseline carries no company data: it is only the nine network nodes' priors,
all-bindings-present posteriors, and interval widths.
"""

from __future__ import annotations

import copy
import json

from validation.drift_check import _BASELINE_PATH, _MARGINAL_BAND, compare, compute_fingerprint


def test_shipped_network_matches_committed_baseline() -> None:
    assert _BASELINE_PATH.exists(), "run `python -m validation.drift_check --update` to create the baseline"
    baseline = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    report = compare(baseline, compute_fingerprint())
    assert not report["drifted"], (
        "the Bayesian network drifted from validation/inference_baseline.json; if the change is "
        "intended, run `python -m validation.drift_check --update` and commit the new baseline "
        f"alongside the network edit. Drift: {report['drift']}"
    )


def test_compare_flags_a_shifted_prior() -> None:
    current = compute_fingerprint()
    baseline = copy.deepcopy(current)
    node = next(iter(baseline["inference"]["nodes"]))
    baseline["inference"]["nodes"][node]["prior"] = round(
        baseline["inference"]["nodes"][node]["prior"] + 5 * _MARGINAL_BAND, 4
    )
    report = compare(baseline, current)
    assert report["drifted"]
    assert any(d["node"] == node and d["field"] == "prior" for d in report["drift"])


def test_compare_ignores_sub_band_wobble() -> None:
    current = compute_fingerprint()
    baseline = copy.deepcopy(current)
    node = next(iter(baseline["inference"]["nodes"]))
    # Half a band: below the meaningful-resolution threshold, so not flagged.
    baseline["inference"]["nodes"][node]["prior"] = round(
        baseline["inference"]["nodes"][node]["prior"] + 0.5 * _MARGINAL_BAND, 4
    )
    assert not compare(baseline, current)["drifted"]


def test_baseline_carries_no_per_domain_data() -> None:
    # The committed baseline must stay corpus-free: node names + numbers only,
    # no apexes / domains / org strings.
    baseline = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    nodes = baseline["inference"]["nodes"]
    assert nodes
    assert all("." not in name for name in nodes)  # node names, never apexes/domains
    for fields in nodes.values():
        assert set(fields) == {"prior", "all_present", "all_present_interval_width"}
        assert all(isinstance(v, int | float) for v in fields.values())
