"""Collection-aware metric construction for posture comparisons."""

from __future__ import annotations

from recon_tool.collection_view import collection_observable_info
from recon_tool.email_security import compute_email_security_score
from recon_tool.exposure_models import PostureMetric
from recon_tool.exposure_observability import ObservableEmailState
from recon_tool.models import TenantInfo


def _score_value(info: TenantInfo, observed: ObservableEmailState) -> str:
    """Render a score only when every constituent channel was collected."""
    if not observed.score_collection_available:
        return "source unavailable"
    return str(compute_email_security_score(info))


def _count_value(count: int, info: TenantInfo) -> str:
    """Qualify a count whose collection opportunity was incomplete."""
    if info.degraded_sources:
        return f"{count} observed (partial collection)"
    return str(count)


def build_metrics(info_a: TenantInfo, info_b: TenantInfo) -> tuple[PostureMetric, ...]:
    """Build side-by-side metrics without turning failed collection into absence."""
    info_a = collection_observable_info(info_a)
    info_b = collection_observable_info(info_b)
    observed_a = ObservableEmailState.from_info(info_a)
    observed_b = ObservableEmailState.from_info(info_b)
    return (
        PostureMetric(
            metric_name="email_security_score",
            domain_a_value=_score_value(info_a, observed_a),
            domain_b_value=_score_value(info_b, observed_b),
        ),
        PostureMetric(
            metric_name="confidence",
            domain_a_value=info_a.confidence.value,
            domain_b_value=info_b.confidence.value,
        ),
        PostureMetric(
            metric_name="auth_type",
            domain_a_value=info_a.auth_type or "",
            domain_b_value=info_b.auth_type or "",
        ),
        PostureMetric(
            metric_name="service_count",
            domain_a_value=_count_value(len(info_a.services), info_a),
            domain_b_value=_count_value(len(info_b.services), info_b),
        ),
        PostureMetric(
            metric_name="dmarc_policy",
            domain_a_value=(observed_a.dmarc_policy or "") if observed_a.dmarc_available else "source unavailable",
            domain_b_value=(observed_b.dmarc_policy or "") if observed_b.dmarc_available else "source unavailable",
        ),
        PostureMetric(
            metric_name="mta_sts_mode",
            domain_a_value=(observed_a.mta_sts_mode or "") if observed_a.mta_sts_available else "source unavailable",
            domain_b_value=(observed_b.mta_sts_mode or "") if observed_b.mta_sts_available else "source unavailable",
        ),
    )
