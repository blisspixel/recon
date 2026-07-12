"""Reproducible, network-free local performance characterization.

This script records stage measurements for deterministic synthetic fixtures. It
is a diagnostic harness, not a timing gate: host load and hardware affect the
numbers, while correctness remains enforced by the normal test suite.
"""

from __future__ import annotations

import argparse
import gc
import io
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import sysconfig
import tempfile
import time
import tracemalloc
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any

from rich.console import Console

from recon_tool.bayesian import infer, load_network
from recon_tool.fingerprints import get_txt_patterns, load_fingerprints, match_txt_all, reload_fingerprints
from recon_tool.formatter import render_tenant_panel
from recon_tool.infra_graph import build_infrastructure_clusters
from recon_tool.models import ConfidenceLevel, TenantInfo


@dataclass(frozen=True, slots=True)
class CharacterizationCase:
    """One deterministic workload and its machine-readable shape."""

    name: str
    shape: dict[str, object]
    operation: Callable[[], object]


@dataclass(frozen=True, slots=True)
class Measurement:
    """Timing and Python-allocation observations for one case."""

    median_ms: float
    p95_ms: float
    maximum_ms: float
    python_peak_kib: float


def _nearest_rank(values: list[float], quantile: float) -> float:
    """Return the nearest-rank sample quantile for a non-empty sequence."""
    if not values:
        raise ValueError("values must not be empty")
    if not 0.0 < quantile <= 1.0:
        raise ValueError("quantile must be in (0, 1]")
    ordered = sorted(values)
    rank = max(1, math.ceil(quantile * len(ordered)))
    return ordered[rank - 1]


def _measure(case: CharacterizationCase, repetitions: int, warmups: int) -> Measurement:
    """Measure one case without turning host-dependent timing into a test."""
    for _ in range(warmups):
        case.operation()

    durations: list[float] = []
    for _ in range(repetitions):
        gc.collect()
        started = time.perf_counter()
        case.operation()
        durations.append(time.perf_counter() - started)

    gc.collect()
    tracemalloc.start()
    try:
        case.operation()
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return Measurement(
        median_ms=round(statistics.median(durations) * 1000, 3),
        p95_ms=round(_nearest_rank(durations, 0.95) * 1000, 3),
        maximum_ms=round(max(durations) * 1000, 3),
        python_peak_kib=round(peak_bytes / 1024, 1),
    )


def _cold_catalog_load() -> int:
    reload_fingerprints()
    return len(load_fingerprints())


@contextmanager
def _isolated_config_directory() -> Generator[None]:
    """Exclude maintainer custom fingerprints from the deterministic fixtures."""
    previous = os.environ.get("RECON_CONFIG_DIR")
    with tempfile.TemporaryDirectory(prefix="recon-characterization-") as directory:
        os.environ["RECON_CONFIG_DIR"] = directory
        reload_fingerprints()
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop("RECON_CONFIG_DIR", None)
            else:
                os.environ["RECON_CONFIG_DIR"] = previous
            reload_fingerprints()


def _match_txt_records(count: int) -> int:
    patterns = get_txt_patterns()
    return sum(len(match_txt_all(f"fictional-verification-token-{index}", patterns)) for index in range(count))


_NETWORK = load_network()


def _infer_domains(count: int) -> int:
    posterior_count = 0
    for _ in range(count):
        result = infer(
            _NETWORK,
            observed_slugs=("microsoft365", "cloudflare", "proofpoint"),
            observed_signals=("email_gateway_mx_observed", "spf_strict"),
            priors_override={},
        )
        posterior_count += len(result.posteriors)
    return posterior_count


def _cluster_graph_entries(node_count: int) -> list[dict[str, object]]:
    """Build disconnected 10-host clusters with one repeated half-clique."""
    entries: list[dict[str, object]] = []
    for cluster_start in range(0, node_count, 10):
        names = [f"host-{index}.example.test" for index in range(cluster_start, min(cluster_start + 10, node_count))]
        entries.append({"dns_names": names, "issuer_name": "Fictional Test CA"})
        if len(names) >= 2:
            entries.append({"dns_names": names[:5], "issuer_name": "Fictional Test CA"})
    return entries


def _dense_graph_entries(
    *,
    entry_count: int = 1000,
    sans_per_entry: int = 20,
    host_pool_size: int = 200,
) -> list[dict[str, object]]:
    """Build a deterministic overlapping SAN workload over a fixed host pool."""
    hosts = [f"host-{index}.example.test" for index in range(host_pool_size)]
    entries: list[dict[str, object]] = []
    for entry_index in range(entry_count):
        start = (entry_index * 7) % host_pool_size
        names = [hosts[(start + offset) % host_pool_size] for offset in range(sans_per_entry)]
        entries.append({"dns_names": names, "issuer_name": f"Fictional CA {entry_index % 3}"})
    return entries


def _repeated_graph_entries(
    *,
    entry_count: int = 1000,
    sans_per_entry: int = 60,
) -> list[dict[str, object]]:
    """Build repeated renewal-like entries with one identical SAN hyperedge."""
    names = [f"host-{index}.example.test" for index in range(sans_per_entry)]
    return [{"dns_names": names, "issuer_name": "Fictional Test CA"} for _ in range(entry_count)]


def _graph_edge_count(entries: list[dict[str, object]]) -> int:
    return build_infrastructure_clusters(entries).edge_count


_PANEL_INFO = TenantInfo(
    tenant_id="00000000-0000-0000-0000-000000000000",
    display_name="Example Organization",
    default_domain="example.test",
    queried_domain="example.test",
    confidence=ConfidenceLevel.HIGH,
    domain_count=1,
    services=tuple(f"Service {index}" for index in range(1000)),
    slugs=tuple(f"service-{index}" for index in range(1000)),
)


def _render_large_panel() -> int:
    stream = io.StringIO()
    console = Console(no_color=True, width=120, file=stream)
    console.print(render_tenant_panel(_PANEL_INFO, show_domains=True, verbose=True))
    return len(stream.getvalue())


def build_cases(*, include_stress: bool) -> tuple[CharacterizationCase, ...]:
    """Return the exact ordered fixture catalog used by this harness."""
    small_graph = _cluster_graph_entries(50)
    medium_graph = _cluster_graph_entries(200)
    cases = [
        CharacterizationCase(
            "fingerprint_catalog_cold_load",
            {"catalog_entries": len(load_fingerprints()), "format": "split_yaml", "cache": "cleared_each_repetition"},
            _cold_catalog_load,
        ),
        CharacterizationCase(
            "fingerprint_match_100_records",
            {"record_count": 100, "pattern_count": len(get_txt_patterns()), "records": "synthetic_nonmatching"},
            lambda: _match_txt_records(100),
        ),
        CharacterizationCase(
            "fingerprint_match_1000_records",
            {"record_count": 1000, "pattern_count": len(get_txt_patterns()), "records": "synthetic_nonmatching"},
            lambda: _match_txt_records(1000),
        ),
        CharacterizationCase(
            "bayesian_inference_1_domain",
            {"domain_count": 1, "network_nodes": len(_NETWORK.nodes), "network": "shipped"},
            lambda: _infer_domains(1),
        ),
        CharacterizationCase(
            "bayesian_inference_100_domains",
            {"domain_count": 100, "network_nodes": len(_NETWORK.nodes), "execution": "sequential"},
            lambda: _infer_domains(100),
        ),
        CharacterizationCase(
            "ct_graph_50_nodes",
            {"node_count": 50, "entry_count": len(small_graph), "cluster_size": 10, "repeated_half_clique": True},
            lambda: _graph_edge_count(small_graph),
        ),
        CharacterizationCase(
            "ct_graph_200_nodes",
            {"node_count": 200, "entry_count": len(medium_graph), "cluster_size": 10, "repeated_half_clique": True},
            lambda: _graph_edge_count(medium_graph),
        ),
        CharacterizationCase(
            "panel_render_1000_services",
            {"service_count": 1000, "width": 120, "verbose": True, "show_domains": True},
            _render_large_panel,
        ),
    ]
    if include_stress:
        dense_graph = _dense_graph_entries()
        repeated_graph = _repeated_graph_entries()
        cases.extend(
            [
                CharacterizationCase(
                    "ct_graph_dense_1000x20",
                    {
                        "entry_count": 1000,
                        "sans_per_entry": 20,
                        "host_pool_size": 200,
                        "start_stride": 7,
                        "issuer_cycle": 3,
                    },
                    lambda: _graph_edge_count(dense_graph),
                ),
                CharacterizationCase(
                    "ct_graph_repeated_1000x60",
                    {"entry_count": 1000, "sans_per_entry": 60, "identical_hyperedge": True, "issuer_count": 1},
                    lambda: _graph_edge_count(repeated_graph),
                ),
            ]
        )
    return tuple(cases)


def _git_metadata() -> tuple[str | None, bool | None]:
    git = shutil.which("git")
    if git is None:
        return None, None
    revision = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
        [git, "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        cwd=os.fspath(os.path.dirname(os.path.dirname(__file__))),
        text=True,
    )
    status = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
        [git, "status", "--porcelain"],
        check=False,
        capture_output=True,
        cwd=os.fspath(os.path.dirname(os.path.dirname(__file__))),
        text=True,
    )
    head_text = revision.stdout.strip() if revision.returncode == 0 else ""
    head = head_text or None
    dirty = bool(status.stdout.strip()) if status.returncode == 0 else None
    return head, dirty


def characterize(*, repetitions: int, warmups: int, include_stress: bool) -> dict[str, Any]:
    """Run the selected cases and return a JSON-serializable report."""
    if repetitions < 1:
        raise ValueError("repetitions must be at least 1")
    if warmups < 0:
        raise ValueError("warmups must be at least 0")
    with _isolated_config_directory():
        cases = build_cases(include_stress=include_stress)
        measurements = {
            case.name: {"shape": case.shape, **asdict(_measure(case, repetitions, warmups))} for case in cases
        }
    commit, working_tree_dirty = _git_metadata()
    return {
        "schema_version": 1,
        "environment": {
            "commit": commit,
            "working_tree_dirty": working_tree_dirty,
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "free_threaded_build": sysconfig.get_config_var("Py_GIL_DISABLED") == 1,
            "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "method": {
            "repetitions": repetitions,
            "warmups": warmups,
            "timer": "time.perf_counter",
            "p95": "nearest_rank",
            "allocation": "single_tracemalloc_run_after_timing",
            "network": "disabled",
            "custom_config": "disabled_with_empty_temporary_directory",
        },
        "measurements": measurements,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=9, help="Timed repetitions per case (default: 9).")
    parser.add_argument("--warmups", type=int, default=1, help="Untimed warm-ups per case (default: 1).")
    parser.add_argument("--skip-stress", action="store_true", help="Skip the two bounded CT graph stress cases.")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be at least 1")
    if args.warmups < 0:
        parser.error("--warmups must be at least 0")
    report = characterize(
        repetitions=args.repetitions,
        warmups=args.warmups,
        include_stress=not args.skip_stress,
    )
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
