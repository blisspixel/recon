"""Aggregate-only live characterization for the v2.11 product-quality baseline.

This maintainer tool measures the real resolver on a private corpus while
keeping every apex and per-domain row inside process memory. The only written
artifact contains counts, quantiles, bounded source markers, environment data,
and digests. It never enables the optional direct Google CSE or BIMI probes.

Network execution requires the explicit ``--execute-network`` acknowledgement::

    python -m validation.characterize_live_quality \
        --corpus validation/corpus-private/quality-characterization.txt \
        --output validation/runs-private/<stamp>/characterization.json \
        --network-class wired \
        --execute-network

The corpus must contain one lowercase canonical apex per non-comment line.
Inputs and outputs inside the checkout are accepted only under the established
gitignored private validation roots. Existing output files are never replaced.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import tracemalloc
from collections import Counter, defaultdict
from collections.abc import Generator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, cast

from recon_tool.bayesian import infer_from_tenant_info
from recon_tool.cache import cache_get as disk_cache_get
from recon_tool.cache import cache_put as disk_cache_put
from recon_tool.cache_insights import validate_insight_claim_coverage
from recon_tool.formatter import format_tenant_json
from recon_tool.mcp_client.sdk_compat import SDK_FAMILY, SDK_VERSION, model_wire_dict
from recon_tool.merger import merge_results
from recon_tool.models import ReconLookupError, SourceResult, TenantInfo
from recon_tool.resolver import SourcePool, default_pool, resolve_tenant
from recon_tool.validator import validate_domain
from validation.run_path_safety import validate_private_output_root

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOTS = (
    REPO_ROOT / "validation" / "corpus-private",
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "live_runs",
    REPO_ROOT / "validation" / "local",
)
_SAFE_MARKER_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")
_SAFE_SEED_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
_MAX_FRAME_ROWS = 500
_MAX_SOURCE_ROWS = 10_000
_HEARTBEAT_SECONDS = 0.01


@dataclass(frozen=True, slots=True)
class RunObservation:
    """One in-memory measurement. No target identifier is representable."""

    ct_enabled: bool
    success: bool
    failure_kind: str | None
    resolver_seconds: float | None
    peak_allocation_bytes: int
    maximum_event_loop_lag_seconds: float
    slow_callback_count: int
    stage_seconds: tuple[tuple[str, float], ...]
    degraded_markers: tuple[str, ...]
    unavailable_source_count: int
    partial: bool
    slugs: frozenset[str]
    services: frozenset[str]
    evidence_count: int
    related_domain_count: int
    surface_attribution_count: int
    insight_count: int
    ct_subdomain_count: int
    ct_attempt_outcome: str | None
    json_result_bytes: int | None
    disk_cache_write_seconds: float | None
    warm_disk_read_render_seconds: float | None
    mcp_warm_call_seconds: float | None
    mcp_result_wire_bytes: int | None


@dataclass(frozen=True, slots=True)
class MeasurementConfig:
    timeout: float
    slow_callback_seconds: float


@dataclass(frozen=True, slots=True)
class SelectionOptions:
    """Bounded, explicit preparation rules for a private source corpus."""

    maximum_rows: int = 50
    sample_size: int | None = None
    sampling_seed: str | None = None
    maximum_source_rows: int = _MAX_SOURCE_ROWS
    normalize_source: bool = False
    exclude_invalid_source: bool = False


@dataclass(frozen=True, slots=True)
class CharacterizationConfig:
    frame: FrameSelection
    measurement: MeasurementConfig
    network_class: str
    scratch_root: Path


@dataclass(frozen=True, slots=True)
class FrameSelection:
    """Private membership plus public-safe reproduction metadata."""

    domains: tuple[str, ...]
    source_sha256: str
    selection_sha256: str
    source_input_count: int
    source_eligible_count: int
    normalized_row_count: int
    duplicate_rows_removed: int
    invalid_rows_excluded: int
    invalid_row_policy: str
    source_normalization: str
    sampling_method: str
    sampling_seed: str | None


@dataclass(frozen=True, slots=True)
class _PipelineResult:
    info: TenantInfo
    results: list[SourceResult]
    resolver_seconds: float
    json_text: str
    cache_write_seconds: float
    warm_disk_seconds: float
    mcp_seconds: float
    mcp_bytes: int


@dataclass(frozen=True, slots=True)
class _ExecutionMetrics:
    resolver_seconds: float
    peak_allocation_bytes: int
    maximum_lag: float
    slow_callback_count: int
    stage_seconds: tuple[tuple[str, float], ...]


@dataclass(frozen=True, slots=True)
class _LoggerState:
    logger: logging.Logger
    handlers: tuple[logging.Handler, ...]
    disabled: bool
    propagate: bool
    level: int


class _CharacterizationFailure(RuntimeError):
    """Expected, identifier-free failure classification for one pipeline stage."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        super().__init__(kind)


class _TimedSource:
    """Delegate a source lookup while recording only its fixed source name."""

    def __init__(self, source: Any, samples: dict[str, list[float]]) -> None:
        self._source = source
        self._samples = samples

    @property
    def name(self) -> str:
        return str(self._source.name)

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        started = time.perf_counter()
        try:
            return await self._source.lookup(domain, **kwargs)
        finally:
            self._samples[_safe_marker(self.name)].append(time.perf_counter() - started)


class _SlowCallbackCounter(logging.Handler):
    """Count asyncio slow-callback warnings without retaining their messages."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.count = 0

    def emit(self, record: logging.LogRecord) -> None:
        if record.name == "asyncio" and record.getMessage().startswith("Executing "):
            self.count += 1


@contextlib.contextmanager
def _identifier_safe_logging() -> Generator[None]:
    """Suppress runtime logs while preserving private-target-free metrics."""
    root_logger = logging.getLogger()
    asyncio_logger = logging.getLogger("asyncio")
    registered = [value for value in root_logger.manager.loggerDict.values() if isinstance(value, logging.Logger)]
    loggers = [root_logger, asyncio_logger, *registered]
    states: list[_LoggerState] = []
    seen: set[int] = set()
    for logger in loggers:
        if id(logger) in seen:
            continue
        seen.add(id(logger))
        states.append(
            _LoggerState(
                logger=logger,
                handlers=tuple(logger.handlers),
                disabled=logger.disabled,
                propagate=logger.propagate,
                level=logger.level,
            )
        )
        logger.handlers = [logging.NullHandler()] if logger in (root_logger, asyncio_logger) else []
        logger.propagate = False
        logger.disabled = logger is not asyncio_logger
    try:
        yield
    finally:
        for state in states:
            state.logger.handlers = list(state.handlers)
            state.logger.disabled = state.disabled
            state.logger.propagate = state.propagate
            state.logger.setLevel(state.level)


def _safe_marker(value: str) -> str:
    normalized = value.lower().strip()
    return normalized if _SAFE_MARKER_RE.fullmatch(normalized) else "other"


def _nearest_rank(values: Sequence[float | int], quantile: float) -> float | int:
    if not values:
        raise ValueError("values must not be empty")
    if not 0.0 < quantile <= 1.0:
        raise ValueError("quantile must be in (0, 1]")
    ordered = sorted(values)
    index = max(0, int(quantile * len(ordered) + 0.999999999) - 1)
    return ordered[index]


def _numeric_summary(values: Sequence[float | int], *, decimals: int = 6) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "minimum": None, "p50": None, "p95": None, "maximum": None}

    def _rounded(value: float | int) -> float | int:
        return value if isinstance(value, int) else round(value, decimals)

    return {
        "count": len(values),
        "minimum": _rounded(min(values)),
        "p50": _rounded(_nearest_rank(values, 0.50)),
        "p95": _rounded(_nearest_rank(values, 0.95)),
        "maximum": _rounded(max(values)),
    }


def _validate_sampling_options(options: SelectionOptions) -> None:
    if not 1 <= options.maximum_rows <= _MAX_FRAME_ROWS:
        raise ValueError(f"maximum rows must be between 1 and {_MAX_FRAME_ROWS}")
    if not 1 <= options.maximum_source_rows <= _MAX_SOURCE_ROWS:
        raise ValueError(f"maximum source rows must be between 1 and {_MAX_SOURCE_ROWS}")
    if (options.sample_size is None) != (options.sampling_seed is None):
        raise ValueError("sample size and sampling seed must be provided together")
    if options.sample_size is not None and not 1 <= options.sample_size <= options.maximum_rows:
        raise ValueError("sample size must be between 1 and the declared maximum rows")
    if options.sampling_seed is not None and not _SAFE_SEED_RE.fullmatch(options.sampling_seed):
        raise ValueError("sampling seed must be 1-80 letters, digits, dots, underscores, colons, or hyphens")
    if options.exclude_invalid_source and not options.normalize_source:
        raise ValueError("invalid-row exclusion requires explicit source normalization")


def _normalize_corpus_rows(
    rows: Sequence[str],
    *,
    normalize_source: bool,
    exclude_invalid_source: bool,
) -> tuple[list[str], int, int, int]:
    canonical: list[str] = []
    normalized_count = 0
    invalid_count = 0
    for row in rows:
        try:
            normalized = validate_domain(row)
        except ValueError as exc:
            if not exclude_invalid_source:
                raise ValueError("private characterization corpus contains a malformed row") from exc
            invalid_count += 1
            continue
        if row != normalized:
            if not normalize_source:
                raise ValueError("private characterization corpus rows must be lowercase canonical apexes")
            normalized_count += 1
        canonical.append(normalized)
    duplicate_count = len(canonical) - len(set(canonical))
    if duplicate_count and not normalize_source:
        raise ValueError("private characterization corpus contains duplicate canonical apexes")
    canonical = list(dict.fromkeys(canonical))
    if not canonical:
        raise ValueError("private characterization corpus has no eligible rows after preparation")
    return canonical, normalized_count, duplicate_count, invalid_count


def _canonical_corpus_rows(
    path: Path,
    *,
    options: SelectionOptions,
) -> tuple[list[str], bytes, int, int, int, int]:
    """Read and validate a bounded private source without returning diagnostics."""
    raw = path.read_bytes()
    rows = [
        line.strip() for line in raw.decode("utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    if not rows:
        raise ValueError("private characterization corpus has no eligible rows")
    if len(rows) > options.maximum_source_rows:
        raise ValueError(
            f"private characterization corpus has {len(rows)} rows; source cap is {options.maximum_source_rows}"
        )

    canonical, normalized_count, duplicate_count, invalid_count = _normalize_corpus_rows(
        rows,
        normalize_source=options.normalize_source,
        exclude_invalid_source=options.exclude_invalid_source,
    )
    return canonical, raw, len(rows), normalized_count, duplicate_count, invalid_count


def _load_canonical_corpus(
    path: Path,
    *,
    options: SelectionOptions,
) -> FrameSelection:
    _validate_sampling_options(options)
    canonical, raw, input_count, normalized_count, duplicate_count, invalid_count = _canonical_corpus_rows(
        path, options=options
    )
    if options.sample_size is None:
        if len(canonical) > options.maximum_rows:
            raise ValueError(
                f"private characterization corpus has {len(canonical)} rows; declared cap is {options.maximum_rows}"
            )
        selected = tuple(canonical)
        method = "all-canonical-rows-v1"
    else:
        sampling_seed = cast(str, options.sampling_seed)
        if options.sample_size > len(canonical):
            raise ValueError("sample size exceeds the eligible source row count")
        seed_bytes = sampling_seed.encode("utf-8")
        ranked = sorted(
            canonical,
            key=lambda domain: (hashlib.sha256(seed_bytes + b"\0" + domain.encode("ascii")).digest(), domain),
        )
        selected = tuple(ranked[: options.sample_size])
        method = "sha256-rank-without-replacement-v1"
    selection_bytes = ("\n".join(selected) + "\n").encode("ascii")
    return FrameSelection(
        domains=selected,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        selection_sha256=hashlib.sha256(selection_bytes).hexdigest(),
        source_input_count=input_count,
        source_eligible_count=len(canonical),
        normalized_row_count=normalized_count,
        duplicate_rows_removed=duplicate_count,
        invalid_rows_excluded=invalid_count,
        invalid_row_policy=("exclude-and-count-v1" if options.exclude_invalid_source else "reject-v1"),
        source_normalization=("recon-apex-v1" if options.normalize_source else "strict-canonical-v1"),
        sampling_method=method,
        sampling_seed=options.sampling_seed,
    )


def _validate_private_file(path: Path) -> Path:
    resolved = path.resolve(strict=False)
    validate_private_output_root(resolved.parent, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    return resolved


@contextlib.contextmanager
def _isolated_config_directory(path: Path) -> Generator[None]:
    previous = os.environ.get("RECON_CONFIG_DIR")
    os.environ["RECON_CONFIG_DIR"] = os.fspath(path)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("RECON_CONFIG_DIR", None)
        else:
            os.environ["RECON_CONFIG_DIR"] = previous


async def _event_loop_lag(stop: asyncio.Event) -> list[float]:
    loop = asyncio.get_running_loop()
    samples: list[float] = []
    expected = loop.time() + _HEARTBEAT_SECONDS
    while not stop.is_set():
        timeout = max(0.0, expected - loop.time())
        try:
            await asyncio.wait_for(stop.wait(), timeout=timeout)
        except TimeoutError:
            now = loop.time()
            samples.append(max(0.0, now - expected))
            expected += _HEARTBEAT_SECONDS
    return samples


@contextlib.contextmanager
def _asyncio_debug_capture(threshold_seconds: float) -> Generator[_SlowCallbackCounter]:
    loop = asyncio.get_running_loop()
    logger = logging.getLogger("asyncio")
    handler = _SlowCallbackCounter()
    previous_debug = loop.get_debug()
    previous_threshold = loop.slow_callback_duration
    previous_handlers = list(logger.handlers)
    previous_propagate = logger.propagate
    previous_level = logger.level
    loop.set_debug(True)
    loop.slow_callback_duration = threshold_seconds
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.WARNING)
    try:
        yield handler
    finally:
        loop.set_debug(previous_debug)
        loop.slow_callback_duration = previous_threshold
        logger.handlers = previous_handlers
        logger.propagate = previous_propagate
        logger.setLevel(previous_level)


def _call_result_wire(result: Any) -> dict[str, Any]:
    if not isinstance(result, tuple):
        return model_wire_dict(result)
    content, structured = result
    wire: dict[str, Any] = {
        "content": [model_wire_dict(item) for item in content],
        "isError": False,
    }
    if structured is not None:
        wire["structuredContent"] = structured
    return wire


async def _measure_warm_mcp(domain: str, info: TenantInfo, results: list[SourceResult]) -> tuple[float, int]:
    from recon_tool.server.app import mcp
    from recon_tool.server.runtime import cache_clear, cache_set, rate_limit_clear

    cache_clear()
    rate_limit_clear()
    cache_set(domain, info, results)
    try:
        started = time.perf_counter()
        result = await mcp.call_tool("lookup_tenant", {"domain": domain, "format": "json", "explain": False})
        elapsed = time.perf_counter() - started
        wire = _call_result_wire(result)
        if wire.get("isError") is True:
            raise _CharacterizationFailure("mcp_tool_error")
        wire_bytes = len(json.dumps(wire, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        return elapsed, wire_bytes
    finally:
        cache_clear()
        rate_limit_clear()


def _failed_observation(ct_enabled: bool, failure_kind: str, metrics: _ExecutionMetrics) -> RunObservation:
    return RunObservation(
        ct_enabled=ct_enabled,
        success=False,
        failure_kind=failure_kind,
        resolver_seconds=metrics.resolver_seconds,
        peak_allocation_bytes=metrics.peak_allocation_bytes,
        maximum_event_loop_lag_seconds=metrics.maximum_lag,
        slow_callback_count=metrics.slow_callback_count,
        stage_seconds=metrics.stage_seconds,
        degraded_markers=(),
        unavailable_source_count=0,
        partial=False,
        slugs=frozenset(),
        services=frozenset(),
        evidence_count=0,
        related_domain_count=0,
        surface_attribution_count=0,
        insight_count=0,
        ct_subdomain_count=0,
        ct_attempt_outcome=None,
        json_result_bytes=None,
        disk_cache_write_seconds=None,
        warm_disk_read_render_seconds=None,
        mcp_warm_call_seconds=None,
        mcp_result_wire_bytes=None,
    )


async def _run_pipeline(
    domain: str,
    *,
    ct_enabled: bool,
    timeout: float,
    pool: SourcePool,
    stage_samples: dict[str, list[float]],
) -> _PipelineResult:
    resolver_started = time.perf_counter()
    info, results = await resolve_tenant(
        domain,
        pool=pool,
        timeout=timeout,
        skip_ct=not ct_enabled,
        active_probes=False,
    )
    resolver_seconds = time.perf_counter() - resolver_started

    replay_started = time.perf_counter()
    merge_results(results, domain)
    stage_samples["merge_replay"].append(time.perf_counter() - replay_started)
    inference_started = time.perf_counter()
    infer_from_tenant_info(info)
    stage_samples["inference"].append(time.perf_counter() - inference_started)
    render_started = time.perf_counter()
    json_text = format_tenant_json(info)
    stage_samples["json_render"].append(time.perf_counter() - render_started)

    write_started = time.perf_counter()
    try:
        validate_insight_claim_coverage(info)
    except ValueError as exc:
        raise _CharacterizationFailure("cache_claim_validation") from exc
    disk_cache_put(domain, info)
    cache_write_seconds = time.perf_counter() - write_started
    read_started = time.perf_counter()
    cached = disk_cache_get(domain)
    if cached is None:
        raise _CharacterizationFailure("cache_roundtrip_miss")
    format_tenant_json(cached)
    warm_disk_seconds = time.perf_counter() - read_started
    mcp_seconds, mcp_bytes = await _measure_warm_mcp(domain, info, results)
    return _PipelineResult(
        info=info,
        results=results,
        resolver_seconds=resolver_seconds,
        json_text=json_text,
        cache_write_seconds=cache_write_seconds,
        warm_disk_seconds=warm_disk_seconds,
        mcp_seconds=mcp_seconds,
        mcp_bytes=mcp_bytes,
    )


def _successful_observation(
    ct_enabled: bool,
    pipeline: _PipelineResult,
    metrics: _ExecutionMetrics,
) -> RunObservation:
    info = pipeline.info
    degraded = tuple(sorted(_safe_marker(marker) for marker in info.degraded_sources))
    partial = any(marker not in {"crt.sh", "certspotter"} for marker in degraded)
    return RunObservation(
        ct_enabled=ct_enabled,
        success=True,
        failure_kind=None,
        resolver_seconds=pipeline.resolver_seconds,
        peak_allocation_bytes=metrics.peak_allocation_bytes,
        maximum_event_loop_lag_seconds=metrics.maximum_lag,
        slow_callback_count=metrics.slow_callback_count,
        stage_seconds=metrics.stage_seconds,
        degraded_markers=degraded,
        unavailable_source_count=sum(result.source_unavailable for result in pipeline.results),
        partial=partial,
        slugs=frozenset(info.slugs),
        services=frozenset(info.services),
        evidence_count=len(info.evidence),
        related_domain_count=len(info.related_domains),
        surface_attribution_count=len(info.surface_attributions),
        insight_count=len(info.insights),
        ct_subdomain_count=info.ct_subdomain_count,
        ct_attempt_outcome=_safe_marker(info.ct_attempt_outcome) if info.ct_attempt_outcome else None,
        json_result_bytes=len(pipeline.json_text.encode("utf-8")),
        disk_cache_write_seconds=pipeline.cache_write_seconds,
        warm_disk_read_render_seconds=pipeline.warm_disk_seconds,
        mcp_warm_call_seconds=pipeline.mcp_seconds,
        mcp_result_wire_bytes=pipeline.mcp_bytes,
    )


async def _measure_one(domain: str, *, ct_enabled: bool, config: MeasurementConfig) -> RunObservation:
    stage_samples: dict[str, list[float]] = defaultdict(list)
    pool = SourcePool([_TimedSource(source, stage_samples) for source in default_pool()])
    stop = asyncio.Event()
    lag_task = asyncio.create_task(_event_loop_lag(stop))
    tracing_already_active = tracemalloc.is_tracing()
    if not tracing_already_active:
        tracemalloc.start()
    before_current, _before_peak = tracemalloc.get_traced_memory()
    tracemalloc.reset_peak()
    resolver_started = time.perf_counter()
    failure_kind: str | None = None
    pipeline: _PipelineResult | None = None
    with _asyncio_debug_capture(config.slow_callback_seconds) as slow_callbacks:
        try:
            pipeline = await _run_pipeline(
                domain,
                ct_enabled=ct_enabled,
                timeout=config.timeout,
                pool=pool,
                stage_samples=stage_samples,
            )
        except ReconLookupError as exc:
            failure_kind = _safe_marker(exc.error_type)
        except _CharacterizationFailure as exc:
            failure_kind = _safe_marker(exc.kind)
        except asyncio.CancelledError:
            raise
        except Exception:
            failure_kind = "unexpected_error"
        finally:
            await asyncio.sleep(0)
            _current, peak = tracemalloc.get_traced_memory()
            peak_allocation = max(0, peak - before_current)
            stop.set()
            lag_samples = await lag_task
            maximum_lag = max(lag_samples, default=0.0)
            if not tracing_already_active:
                tracemalloc.stop()
    resolver_seconds = pipeline.resolver_seconds if pipeline is not None else time.perf_counter() - resolver_started
    metrics = _ExecutionMetrics(
        resolver_seconds=resolver_seconds,
        peak_allocation_bytes=peak_allocation,
        maximum_lag=maximum_lag,
        slow_callback_count=slow_callbacks.count,
        stage_seconds=tuple(sorted((name, elapsed) for name, values in stage_samples.items() for elapsed in values)),
    )
    if pipeline is None or failure_kind is not None:
        return _failed_observation(ct_enabled, failure_kind or "unexpected_error", metrics)
    return _successful_observation(ct_enabled, pipeline, metrics)


def _mode_summary(observations: Sequence[RunObservation]) -> dict[str, Any]:
    successful = [observation for observation in observations if observation.success]
    stages: dict[str, list[float]] = defaultdict(list)
    for observation in observations:
        for name, elapsed in observation.stage_seconds:
            stages[name].append(elapsed)
    degraded = Counter(marker for observation in successful for marker in observation.degraded_markers)
    outcomes = Counter(
        observation.ct_attempt_outcome for observation in successful if observation.ct_attempt_outcome is not None
    )

    def _present(field: str) -> list[Any]:
        return [value for observation in successful if (value := getattr(observation, field)) is not None]

    return {
        "attempted": len(observations),
        "succeeded": len(successful),
        "failed": len(observations) - len(successful),
        "failure_kinds": dict(sorted(Counter(o.failure_kind for o in observations if o.failure_kind).items())),
        "partial_results": sum(observation.partial for observation in successful),
        "unavailable_source_observations": sum(observation.unavailable_source_count for observation in successful),
        "degraded_markers": dict(sorted(degraded.items())),
        "ct_attempt_outcomes": dict(sorted(outcomes.items())),
        "resolver_seconds": _numeric_summary(_present("resolver_seconds")),
        "peak_allocation_bytes": _numeric_summary(_present("peak_allocation_bytes"), decimals=0),
        "maximum_event_loop_lag_seconds": _numeric_summary(_present("maximum_event_loop_lag_seconds")),
        "slow_callback_count": sum(observation.slow_callback_count for observation in observations),
        "stage_seconds": {name: _numeric_summary(values) for name, values in sorted(stages.items())},
        "disk_cache_write_seconds": _numeric_summary(_present("disk_cache_write_seconds")),
        "warm_disk_read_render_seconds": _numeric_summary(_present("warm_disk_read_render_seconds")),
        "mcp_warm_call_seconds": _numeric_summary(_present("mcp_warm_call_seconds")),
        "json_result_bytes": _numeric_summary(_present("json_result_bytes"), decimals=0),
        "mcp_result_wire_bytes": _numeric_summary(_present("mcp_result_wire_bytes"), decimals=0),
    }


def _ct_value_summary(pairs: Sequence[tuple[RunObservation, RunObservation]]) -> dict[str, Any]:
    eligible = [(without, with_ct) for without, with_ct in pairs if without.success and with_ct.success]
    latency_deltas = [
        with_ct.resolver_seconds - without.resolver_seconds
        for without, with_ct in eligible
        if without.resolver_seconds is not None and with_ct.resolver_seconds is not None
    ]
    added_slug_counts = [len(with_ct.slugs - without.slugs) for without, with_ct in eligible]
    removed_slug_counts = [len(without.slugs - with_ct.slugs) for without, with_ct in eligible]
    added_service_counts = [len(with_ct.services - without.services) for without, with_ct in eligible]
    removed_service_counts = [len(without.services - with_ct.services) for without, with_ct in eligible]
    evidence_deltas = [with_ct.evidence_count - without.evidence_count for without, with_ct in eligible]
    related_deltas = [with_ct.related_domain_count - without.related_domain_count for without, with_ct in eligible]
    surface_deltas = [
        with_ct.surface_attribution_count - without.surface_attribution_count for without, with_ct in eligible
    ]
    insight_deltas = [with_ct.insight_count - without.insight_count for without, with_ct in eligible]
    any_gain = [
        any(value > 0 for value in values)
        for values in zip(
            added_slug_counts,
            added_service_counts,
            evidence_deltas,
            related_deltas,
            surface_deltas,
            strict=True,
        )
    ]
    return {
        "paired_attempts": len(pairs),
        "eligible_success_pairs": len(eligible),
        "ct_resolver_latency_delta_seconds": _numeric_summary(latency_deltas),
        "pairs_with_any_observable_gain": sum(any_gain),
        "added_slug_count": _numeric_summary(added_slug_counts, decimals=0),
        "removed_slug_count": _numeric_summary(removed_slug_counts, decimals=0),
        "added_service_count": _numeric_summary(added_service_counts, decimals=0),
        "removed_service_count": _numeric_summary(removed_service_counts, decimals=0),
        "evidence_count_delta": _numeric_summary(evidence_deltas, decimals=0),
        "related_domain_count_delta": _numeric_summary(related_deltas, decimals=0),
        "surface_attribution_count_delta": _numeric_summary(surface_deltas, decimals=0),
        "insight_count_delta": _numeric_summary(insight_deltas, decimals=0),
    }


def _distribution_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def _git_metadata() -> dict[str, object]:
    git = shutil.which("git")
    if git is None:
        return {"commit": None, "working_tree_dirty": None}
    revision = subprocess.run(  # noqa: S603 - resolved git executable and fixed argv
        [git, "rev-parse", "HEAD"], cwd=REPO_ROOT, check=False, capture_output=True, text=True
    )
    status = subprocess.run(  # noqa: S603 - resolved git executable and fixed argv
        [git, "status", "--porcelain"], cwd=REPO_ROOT, check=False, capture_output=True, text=True
    )
    return {
        "commit": revision.stdout.strip() if revision.returncode == 0 else None,
        "working_tree_dirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
    }


async def characterize(
    domains: Sequence[str],
    *,
    config: CharacterizationConfig,
) -> dict[str, Any]:
    # Register the actual MCP surface before timing begins so warm tool-call
    # latency does not include one-time module discovery or schema generation.
    __import__("recon_tool.server")
    from recon_tool.server.app import mcp

    await mcp.list_tools()
    observations: list[RunObservation] = []
    pairs: list[tuple[RunObservation, RunObservation]] = []
    started_at = datetime.now(UTC)
    for index, domain in enumerate(domains):
        order = (False, True) if index % 2 == 0 else (True, False)
        paired: dict[bool, RunObservation] = {}
        for ct_enabled in order:
            config_dir = config.scratch_root / f"unit-{index:04d}-{'ct' if ct_enabled else 'no-ct'}"
            config_dir.mkdir(parents=True, exist_ok=False)
            with _isolated_config_directory(config_dir):
                observation = await _measure_one(
                    domain,
                    ct_enabled=ct_enabled,
                    config=config.measurement,
                )
            observations.append(observation)
            paired[ct_enabled] = observation
        pairs.append((paired[False], paired[True]))
    finished_at = datetime.now(UTC)

    without_ct = [observation for observation in observations if not observation.ct_enabled]
    with_ct = [observation for observation in observations if observation.ct_enabled]
    return {
        "schema_version": 1,
        "observed_at": finished_at.isoformat(),
        "repository": _git_metadata(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or None,
            "recon_tool": _distribution_version("recon-tool"),
            "mcp_sdk": str(SDK_VERSION),
            "mcp_sdk_family": SDK_FAMILY,
            "network_class": config.network_class,
        },
        "frame": {
            "source_sha256": config.frame.source_sha256,
            "selection_sha256": config.frame.selection_sha256,
            "source_input_count": config.frame.source_input_count,
            "source_eligible_count": config.frame.source_eligible_count,
            "normalized_row_count": config.frame.normalized_row_count,
            "duplicate_rows_removed": config.frame.duplicate_rows_removed,
            "invalid_rows_excluded": config.frame.invalid_rows_excluded,
            "invalid_row_policy": config.frame.invalid_row_policy,
            "source_normalization": config.frame.source_normalization,
            "eligible_domain_count": len(domains),
            "sampling_method": config.frame.sampling_method,
            "sampling_seed": config.frame.sampling_seed,
            "identifiers_written": 0,
            "per_domain_rows_written": 0,
        },
        "method": {
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "elapsed_seconds": round((finished_at - started_at).total_seconds(), 6),
            "execution": "sequential",
            "ct_pair_order": "alternating by private-frame row parity",
            "result_cache": "isolated empty config per domain and mode",
            "warm_disk": "write fresh TenantInfo, then cache read plus JSON render",
            "warm_mcp": "seed in-process result cache, then actual lookup_tenant tool call",
            "active_probes": False,
            "runtime_logging": "suppressed to protect private frame identifiers",
            "default_target_owned_http": "MTA-STS only",
            "resolver_timeout_seconds": config.measurement.timeout,
            "asyncio_debug": True,
            "slow_callback_threshold_seconds": config.measurement.slow_callback_seconds,
            "event_loop_heartbeat_seconds": _HEARTBEAT_SECONDS,
            "tracemalloc": "per cold resolve plus merge replay, inference, render, cache, and MCP warm call",
        },
        "modes": {
            "ct_disabled": _mode_summary(without_ct),
            "ct_enabled": _mode_summary(with_ct),
        },
        "paired_ct_value": _ct_value_summary(pairs),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True, help="Private file with one canonical apex per line.")
    parser.add_argument("--output", type=Path, required=True, help="New private aggregate JSON path.")
    parser.add_argument(
        "--network-class",
        choices=("wired", "wifi", "cloud-vm", "ci", "other"),
        required=True,
        help="Coarse environment class recorded with the aggregate.",
    )
    parser.add_argument("--maximum-rows", type=int, default=50, help="Fail if the frame exceeds this cap (max 500).")
    parser.add_argument(
        "--sample-size",
        type=int,
        help="Deterministically select this many rows from a larger private source corpus.",
    )
    parser.add_argument(
        "--sampling-seed",
        help="Public-safe seed required with --sample-size; recorded in the aggregate.",
    )
    parser.add_argument(
        "--normalize-source",
        action="store_true",
        help="Explicitly reduce valid input rows to lowercase canonical apexes and remove resulting duplicates.",
    )
    parser.add_argument(
        "--exclude-invalid-source",
        action="store_true",
        help="Explicitly exclude malformed legacy rows and record their count; requires --normalize-source.",
    )
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-mode resolver timeout in seconds.")
    parser.add_argument(
        "--slow-callback-seconds",
        type=float,
        default=0.05,
        help="Asyncio slow-callback threshold recorded and enforced during characterization.",
    )
    parser.add_argument(
        "--execute-network",
        action="store_true",
        help="Acknowledge public DNS/identity/CT traffic and execute the paired live run.",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Validate paths and frame selection, print safe metadata, and make no network calls or writes.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.execute_network == args.preflight:
        parser.error("choose exactly one of --preflight or --execute-network")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if not 0 < args.slow_callback_seconds <= 1.0:
        parser.error("--slow-callback-seconds must be in (0, 1]")

    try:
        corpus = _validate_private_file(args.corpus)
        output = _validate_private_file(args.output)
        if not corpus.is_file():
            raise ValueError("private characterization corpus does not exist")
        if output.exists():
            raise ValueError("output already exists; choose a new run path")
        frame = _load_canonical_corpus(
            corpus,
            options=SelectionOptions(
                maximum_rows=args.maximum_rows,
                sample_size=args.sample_size,
                sampling_seed=args.sampling_seed,
                normalize_source=args.normalize_source,
                exclude_invalid_source=args.exclude_invalid_source,
            ),
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        parser.error(str(exc))

    if args.preflight:
        print(
            json.dumps(
                {
                    "network": "not used",
                    "writes": 0,
                    "source_sha256": frame.source_sha256,
                    "selection_sha256": frame.selection_sha256,
                    "source_input_count": frame.source_input_count,
                    "source_eligible_count": frame.source_eligible_count,
                    "normalized_row_count": frame.normalized_row_count,
                    "duplicate_rows_removed": frame.duplicate_rows_removed,
                    "invalid_rows_excluded": frame.invalid_rows_excluded,
                    "invalid_row_policy": frame.invalid_row_policy,
                    "source_normalization": frame.source_normalization,
                    "eligible_domain_count": len(frame.domains),
                    "sampling_method": frame.sampling_method,
                    "sampling_seed": frame.sampling_seed,
                    "network_class_for_execution": args.network_class,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    with (
        tempfile.TemporaryDirectory(prefix="quality-characterization-", dir=output.parent) as temporary,
        _identifier_safe_logging(),
    ):
        report = asyncio.run(
            characterize(
                frame.domains,
                config=CharacterizationConfig(
                    frame=frame,
                    measurement=MeasurementConfig(
                        timeout=args.timeout,
                        slow_callback_seconds=args.slow_callback_seconds,
                    ),
                    network_class=args.network_class,
                    scratch_root=Path(temporary),
                ),
            )
        )
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    attempted = report["modes"]["ct_disabled"]["attempted"]
    paired = report["paired_ct_value"]["eligible_success_pairs"]
    print(f"Characterization complete: attempted={attempted}, eligible_ct_pairs={paired}, identifiers_written=0")
    print(f"Aggregate written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
