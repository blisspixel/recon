"""Stateless cohort summary over a batch of recon records.

This is the thin, in-core surface for `recon batch --summary`: one cohort in, one
aggregate-only summary out. It computes live from the per-domain records the batch
already produces and stores nothing. It ships no baselines, makes no
baseline-relative anomaly score, infers no unobserved services, and never names a
domain in its output.

The richer downstream analysis (caller-supplied grouping, distinctive-slug
ranking, partial pooling) lives in the separate reducer under
``validation/aggregate/``, which imports the math and the per-cohort summary from
this module so the two never drift.

What it reports, and why each is the honest choice, is documented in
``docs/aggregate-state.md``. In brief: observed public-claim rates only where a
successful opportunity supplies both positive and authoritative-negative
semantics, model support coverage for hideable infrastructure claims, aggregated
model-score mass kept separate from both, compositional concentration for the
provider and cloud mixes, and small-cell suppression so a tiny cohort does not
read as a census.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from rich.panel import Panel
from rich.text import Text

from recon_tool.source_status import SourceStatus
from recon_tool.validator import strip_control_chars

# 0.9 quantile of the standard normal, for an 80% two-sided interval, matching
# recon's 80% display convention. The summary reports an 80% Wilson
# score interval (closed form); a Jeffreys Beta interval is the Bayesian sibling.
_Z80 = 1.2815515594457

# Small-cell suppression: raw counts in [1, _SUPPRESS_MAX] are withheld from
# output; a cohort below _SMALL_N carries a warning.
_SUPPRESS_MAX = 10
_SMALL_N = 30

COHORT_DISCLAIMER = (
    "Within this caller-supplied cohort only. Declarative rates describe named "
    "public claims; hideable identity entries are model support coverage, not "
    "prevalence. This is not an industry sample or census, and small cohorts "
    "carry wide intervals."
)

# Declarative public claims and hideable model-support signals share one stable
# compatibility block but have different metric semantics.
_PREVALENCE_SIGNALS = (
    "dmarc_reject",
    "dmarc_enforcing",
    "mta_sts_enforce",
    "email_gateway_present",
    "m365_tenant",
    "google_workspace",
)

_MODEL_SUPPORT_SIGNALS = frozenset({"m365_tenant", "google_workspace"})


def wilson_interval(positives: int, n: int, z: float = _Z80) -> tuple[float, float]:
    """80% Wilson score interval for a binomial proportion. Returns (0.0, 1.0)
    for an empty denominator (no information). ``positives`` is clamped to
    ``[0, n]`` so a caller cannot trigger a math-domain error."""
    if n <= 0:
        return (0.0, 1.0)
    positives = max(0, min(positives, n))
    p = positives / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half = (z * math.sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def shannon_entropy(counts: Iterable[float]) -> float:
    """Shannon entropy in bits of a count distribution."""
    vals = [c for c in counts if c > 0]
    total = sum(vals)
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in vals)


def normalized_entropy(counts: Sequence[float]) -> float:
    """Entropy normalized to [0, 1] by the number of non-empty categories. 0 is a
    single-vendor monoculture; 1 is an even spread."""
    nonzero = [c for c in counts if c > 0]
    if len(nonzero) <= 1:
        return 0.0
    return shannon_entropy(nonzero) / math.log2(len(nonzero))


def hhi(counts: Iterable[float]) -> float:
    """Herfindahl-Hirschman index of concentration in [0, 1]. 1 is a monoculture;
    near 0 is fragmented."""
    vals = [c for c in counts if c > 0]
    total = sum(vals)
    if total <= 0:
        return 0.0
    return sum((c / total) ** 2 for c in vals)


def _as_list(value: Any) -> list[Any]:
    """Coerce an external value to a list; non-list/tuple input (from arbitrary
    JSON the downstream reducer ingests) becomes empty so iteration and
    membership checks never raise on a malformed record."""
    return list(value) if isinstance(value, (list, tuple)) else []


def _dns_resolved(record: Mapping[str, Any]) -> bool:
    return not SourceStatus.from_degraded_sources(_as_list(record.get("degraded_sources"))).whole_dns_unavailable


def _posterior_map(record: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    obs = _as_list(record.get("posterior_observations"))
    # The name becomes a dict key, so require a string (hashable); a malformed
    # record with a list/dict name must be skipped, not raise TypeError.
    return {o["name"]: o for o in obs if isinstance(o, Mapping) and isinstance(o.get("name"), str)}


def extract_signals(record: Mapping[str, Any]) -> dict[str, bool | None]:
    """Declarative observations and model support decisions.

    Declarative signals are observable when their collection channel resolved;
    ``None`` means that public classification was unavailable. Hideable Bayesian
    entries are model support decisions only when a non-sparse node has fired
    evidence. Their nonfire is not an authoritative negative observation.
    """
    status = SourceStatus.from_degraded_sources(_as_list(record.get("degraded_sources")))
    posteriors = _posterior_map(record)
    out: dict[str, bool | None] = {}

    dmarc = record.get("dmarc_policy")
    dmarc_available = status.channel_available("dmarc")
    out["dmarc_reject"] = (dmarc == "reject") if dmarc_available else None
    out["dmarc_enforcing"] = (dmarc in ("reject", "quarantine")) if dmarc_available else None
    out["mta_sts_enforce"] = (record.get("mta_sts_mode") == "enforce") if status.channel_available("mta_sts") else None
    out["email_gateway_present"] = (record.get("email_gateway") is not None) if status.channel_available("mx") else None

    for signal, node in (("m365_tenant", "m365_tenant"), ("google_workspace", "google_workspace_tenant")):
        o = posteriors.get(node)
        if o is None or o.get("sparse") or not o.get("evidence_used"):
            out[signal] = None
        else:
            out[signal] = _safe_float(o.get("posterior")) > 0.5
    return out


def _suppressed(count: int) -> int | str:
    """Apply small-cell suppression to a raw count."""
    return "<=10 (suppressed)" if 1 <= count <= _SUPPRESS_MAX else count


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Coerce an external value to a finite float, defaulting on None, non-numeric,
    or non-finite (NaN / inf) input. The downstream reducer ingests arbitrary JSON,
    so a malformed posterior must not crash the run or poison the aggregate math."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return f if math.isfinite(f) else default


def _prevalence_block(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    n = len(records)
    signal_maps = [extract_signals(r) for r in records]
    block: dict[str, Any] = {}
    for sig in _PREVALENCE_SIGNALS:
        vals = [sm[sig] for sm in signal_maps]
        observable = [v for v in vals if v is not None]
        positives = sum(1 for v in observable if v)
        obs_n = len(observable)
        support_coverage = round(positives / n, 4) if n else None
        if sig in _MODEL_SUPPORT_SIGNALS:
            block[sig] = {
                "positives": _suppressed(positives),
                "observable_n": 0,
                "observed_rate": None,
                "observed_rate_interval_80": None,
                "lower_bound_over_cohort": None,
                "observability_fraction": 0.0 if n else None,
                "metric_kind": "model_support_coverage",
                "model_evidence_n": obs_n,
                "support_coverage": support_coverage,
                "unresolved_share": round((n - positives) / n, 4) if n else None,
            }
            continue
        low, high = wilson_interval(positives, obs_n)
        block[sig] = {
            "positives": _suppressed(positives),
            "observable_n": obs_n,
            "observed_rate": round(positives / obs_n, 4) if obs_n else None,
            "observed_rate_interval_80": [round(low, 4), round(high, 4)] if obs_n else None,
            "lower_bound_over_cohort": round(positives / n, 4) if n else None,
            "observability_fraction": round(obs_n / n, 4) if n else None,
            "metric_kind": "authoritative_observed_rate",
            "model_evidence_n": None,
            "support_coverage": support_coverage,
            "unresolved_share": round((n - obs_n) / n, 4) if n else None,
        }
    return block


def _posterior_claims_block(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    n = len(records)
    by_node: dict[str, list[Mapping[str, Any]]] = {}
    for r in records:
        for name, o in _posterior_map(r).items():
            by_node.setdefault(name, []).append(o)
    block: dict[str, Any] = {}
    for node, obs in sorted(by_node.items()):
        posteriors = [min(1.0, max(0.0, _safe_float(o.get("posterior")))) for o in obs]
        widths = [max(0.0, _safe_float(o.get("interval_high")) - _safe_float(o.get("interval_low"))) for o in obs]
        high_conf = sum(1 for o, p in zip(obs, posteriors, strict=True) if p > 0.8 and not o.get("sparse"))
        sparse = sum(1 for o in obs if o.get("sparse"))
        block[node] = {
            "expected_prevalence": round(sum(posteriors) / len(posteriors), 4),
            "high_confidence_share": round(high_conf / n, 4) if n else None,
            "mean_model_score": round(sum(posteriors) / len(posteriors), 4),
            "high_score_share": round(high_conf / n, 4) if n else None,
            "mean_interval_width": round(sum(widths) / len(widths), 4),
            "sparse_share": round(sparse / len(obs), 4),
            "observed_n": len(obs),
        }
    return block


def _mix_block(records: Sequence[Mapping[str, Any]], field: str) -> dict[str, Any]:
    counts = Counter(str(r.get(field)) for r in records if r.get(field) not in (None, "", "unknown"))
    total = sum(counts.values())
    # Deterministic order: count descending, then key ascending. Counter's
    # most_common breaks ties by insertion order, which for a batch is the
    # non-deterministic resolution-completion order.
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    shares = {k: round(v / total, 4) for k, v in ordered} if total else {}
    return {
        "shares": shares,
        "normalized_entropy": round(normalized_entropy(list(counts.values())), 4),
        "hhi": round(hhi(counts.values()), 4),
        "categorized_n": total,
    }


def _observability_block(records: Sequence[Mapping[str, Any]], attempted: int) -> dict[str, Any]:
    n = len(records)
    resolved_dns = sum(1 for r in records if _dns_resolved(r))
    degraded = sum(1 for r in records if r.get("degraded_sources"))
    sparse_shares = []
    for r in records:
        obs = list(_posterior_map(r).values())
        if obs:
            sparse_shares.append(sum(1 for o in obs if o.get("sparse")) / len(obs))
    return {
        "attempted": attempted,
        "resolved": n,
        "resolution_rate": round(n / attempted, 4) if attempted else None,
        "dns_resolved": resolved_dns,
        "degraded_source_rate": round(degraded / n, 4) if n else None,
        "mean_sparse_share": round(sum(sparse_shares) / len(sparse_shares), 4) if sparse_shares else None,
    }


def summarize_cohort(
    records: Sequence[Mapping[str, Any]],
    label: str = "cohort",
    attempted: int | None = None,
) -> dict[str, Any]:
    """The aggregate object for one cohort. Aggregate-only, no domain names.

    ``attempted`` is the number of domains the batch tried, so the observability
    block can report the resolution rate; it defaults to the number of records.
    Near-duplicate inputs that normalize to the same domain (for example a www
    host and its apex) count once among the resolved records, so resolution_rate
    is conservative rather than inflated.
    """
    n = len(records)
    # Resolved can never exceed attempted; guard so resolution_rate stays <= 1.
    attempted = n if attempted is None else max(attempted, n)
    return {
        "label": label,
        "n": n,
        "small_n_warning": n < _SMALL_N,
        "observability": _observability_block(records, attempted),
        "prevalence": _prevalence_block(records),
        "posterior_claims": _posterior_claims_block(records),
        "mix": {
            "provider": _mix_block(records, "provider"),
            "cloud": _mix_block(records, "cloud_instance"),
        },
    }


def build_summary_document(
    records: Sequence[Mapping[str, Any]],
    label: str = "cohort",
    attempted: int | None = None,
) -> dict[str, Any]:
    """The full single-cohort ``--summary`` document: the envelope (record type,
    schema version, disclaimer, suppression policy) plus the cohort's blocks."""
    return {
        "record_type": "cohort_summary",
        "schema_version": "2.1",
        "disclaimer": COHORT_DISCLAIMER,
        "suppression_policy": f"counts 1..{_SUPPRESS_MAX} withheld; small-n warning below {_SMALL_N}",
        **summarize_cohort(records, label, attempted),
    }


def _fmt_pct(value: float | None) -> str:
    return "n/a" if value is None else f"{round(value * 100)}%"


def _fmt_rate(stat: Mapping[str, Any]) -> str:
    """Compact observed-rate with interval and observability for the panel."""
    if stat.get("metric_kind") == "model_support_coverage":
        coverage = stat.get("support_coverage")
        if coverage in (None, 0.0):
            return "no model-supported claims"
        return f"{_fmt_pct(coverage)} model support coverage"
    rate = stat.get("observed_rate")
    if rate is None:
        return "not observable"
    interval = stat.get("observed_rate_interval_80") or [0.0, 0.0]
    obs_frac = stat.get("observability_fraction")
    tail = "" if obs_frac in (None, 1.0) else f", seen for {_fmt_pct(obs_frac)}"
    return f"{_fmt_pct(rate)} [{_fmt_pct(interval[0])}-{_fmt_pct(interval[1])}]{tail}"


def _fmt_mix(mix: Mapping[str, Any]) -> str:
    shares = mix.get("shares") or {}
    if not shares:
        return "not observable"
    # Sanitize record-derived keys (e.g. cloud_instance from OIDC discovery)
    # before they reach the terminal, matching the single-domain panel.
    top = ", ".join(f"{strip_control_chars(str(k))} {_fmt_pct(v)}" for k, v in list(shares.items())[:3])
    return f"{top}  (HHI {mix.get('hhi')})"


def render_cohort_summary(summary: Mapping[str, Any]) -> Panel:
    """Render the cohort summary as a compact, hedged panel."""
    obs = summary.get("observability") or {}
    prev = summary.get("prevalence") or {}
    mix = summary.get("mix") or {}
    body = Text()

    resolved = obs.get("resolved", summary.get("n", 0))
    attempted = obs.get("attempted", resolved)
    body.append("Cohort       ", style="dim")
    warn = "  (small cohort, wide intervals)" if summary.get("small_n_warning") else ""
    body.append(f"{resolved} resolved of {attempted}{warn}\n")
    body.append("Observable   ", style="dim")
    body.append(f"DNS up {obs.get('dns_resolved', 0)}, mean sparse share {obs.get('mean_sparse_share')}\n")

    body.append("Email        ", style="dim")
    body.append(
        f"DMARC enforcing {_fmt_rate(prev.get('dmarc_enforcing', {}))}; "
        f"MTA-STS {_fmt_rate(prev.get('mta_sts_enforce', {}))}\n"
    )
    body.append("Identity     ", style="dim")
    body.append(
        f"M365 {_fmt_rate(prev.get('m365_tenant', {}))}; Workspace {_fmt_rate(prev.get('google_workspace', {}))}\n"
    )
    body.append("Providers    ", style="dim")
    body.append(f"{_fmt_mix(mix.get('provider', {}))}\n")
    body.append("Cloud        ", style="dim")
    body.append(f"{_fmt_mix(mix.get('cloud', {}))}\n")
    body.append(COHORT_DISCLAIMER, style="dim")

    return Panel(body, title="Cohort summary", title_align="left", border_style="dim")
