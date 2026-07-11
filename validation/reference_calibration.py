"""Compare the email-policy model score with the public DMARC channel.

Most recon claims have no predictor-disjoint passive reference. See
correlation.md section 3.3 and docs/statistical-assurance.md.
``email_security_policy_enforcing`` infers a
probability that a domain's email-authentication policy is enforcing.
An observed DMARC channel supplies a public comparison label: ``reject`` or
``quarantine`` is enforcing, while ``none`` or a successfully observed missing
record is not enforcing (RFC 9989). A collection failure is unlabeled rather
than silently converted into a negative. Because DMARC is also the dominant predictor input,
the full-score comparison is overlapping corroboration, not independent
calibration.

What this measures, and what it does not. The reference label here comes
from the observed DMARC channel rather than recon's posterior. The full-score
comparison is nevertheless selected-list corroboration, not independent
calibration: the node's own evidence includes the DMARC signal, so predictor
and label overlap on input. What it does test honestly is whether recon's combined
multi-signal posterior (DMARC plus strict SPF plus MTA-STS, under the
  node's definition) agrees with the authoritative DMARC-only
definition. Where recon over-weights SPF or MTA-STS and reports a high
posterior on a domain whose DMARC is ``p=none``, the reference catches it.

The held-out residual, computed alongside. To remove that input overlap
entirely, each run also computes a *held-out residual* posterior: the same
inference with the ``dmarc_policy`` evidence unit masked as structurally
unobserved (``infer(..., masked_units=("dmarc_policy",))``), so the
predictor sees only the strict-SPF and MTA-STS channel and the DMARC
observation serves purely as the label. Masking is not the same as the signal
not firing — the policy node is declarative, so a non-firing DMARC group
would count as disconfirming absence; the mask suppresses both directions
(see ``recon_tool/bayesian.py``). Predictor and label are disjoint inside
recon's computation. This residual evaluation asks how much the remaining
public channel says about the DMARC declaration on the selected corpus. It does
not make the observations statistically independent, remove shared causes, or
turn a convenience sample into a population sample. Expect the residual to be
much weaker than the full score because DMARC is the dominant input by design.
Its reliability and proper scores are descriptive results for the evaluated
corpus.

Why score reliability and not band coverage. The reference label is binary
(enforcing or not), and the uncertainty band is over a model probability, so
"does the 80% interval contain the label" is a category mismatch.
Reliability against a binary label is the measurable thing: bin the
posteriors and check the empirical enforcing-rate in each bin against
the posterior (reliability / ECE), and score the posterior against the
label (Brier). Frequentist coverage would need a defined repeated-data target
and sampling design. The synthetic perturbation harness
(``validation/interval_coverage.py``) supplies only finite model-relative
scenario containment, not empirical coverage; this harness supplies a
real-record score comparison. Masking the label-defining unit
removes direct predictor-label input overlap; it does not establish sample or
channel independence.

Data handling. The harness reads real apex domains (a public DMARC
record is read for each), so a run stays maintainer-local against the
gitignored corpus and emits aggregates only: no apex, no per-domain row
reaches stdout or any committed file (docs/data-handling-policy.md). The
pure functions below carry no target data and are unit-tested
(tests/test_reference_calibration.py); the orchestration is the
maintainer-run part.

Run (maintainer-local, network):

    python -m validation.reference_calibration domains.txt
    python -m validation.reference_calibration domains.txt --bins 10 --concurrency 5
    python -m validation.reference_calibration domains.txt --json   # structured aggregates
    python -m validation.reference_calibration --stratify-dir by-vertical/ --json

The ``--json`` form emits the same aggregates as a machine-readable object
(no apex, same data-handling rule) so two lists can be compared for agreement
programmatically and the PV2 drift loop can diff release-over-release.
"""

# Reuses the tested calibration internals (_brier / _reliability_table /
# _expected_calibration_error) from synthetic_calibration, the single source for
# this math; legitimate cross-harness reuse, the same allowance the other
# validation harnesses take.
# pyright: reportPrivateUsage=false
from __future__ import annotations

import argparse
import asyncio
import json
import math
import sys
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.source_status import SourceStatus  # noqa: E402
from validation.calibration_estimators import (  # noqa: E402
    bootstrap_mean_confidence_ece,
    equal_mass_reliability_bins,
)
from validation.progress import gather_with_progress  # noqa: E402
from validation.synthetic_calibration import (  # noqa: E402
    _brier,
    _expected_calibration_error,
    _reliability_table,
)

# The node this harness calibrates and the policy levels that count as the
# authoritative "enforcing" ground truth (RFC 9989: reject and quarantine
# are enforcing; none is not).
_POLICY_NODE = "email_security_policy_enforcing"
_ENFORCING_POLICIES = frozenset({"reject", "quarantine"})
_NON_ENFORCING_POLICIES = frozenset({"none"})

# The evidence unit masked for the held-out residual: the mutually-exclusive
# DMARC policy-level group, which is also what defines the reference label.
_DMARC_UNIT = "dmarc_policy"
_ECE_BOOTSTRAP_SAMPLES = 400


def held_out_policy_posterior(
    slugs: set[str],
    signals: set[str],
    network: object | None = None,
    degraded_sources: Collection[str] = (),
) -> float | None:
    """The policy-node posterior with the DMARC evidence unit masked.

    This is the held-out residual predictor: inference over the same
    observation set but with the ``dmarc_policy`` unit treated as
    structurally unobserved, so the DMARC record influences the label only.
    Returns None if the policy node is absent (a custom network). Inference is
    always pinned to the committed priors; user-local prior overrides are not
    part of a reproducible validation experiment.
    """
    from recon_tool.bayesian import collection_masked_units, infer, load_network

    net = network if network is not None else load_network()
    masked_units = set(collection_masked_units(degraded_sources, network=net))  # type: ignore[arg-type]
    masked_units.add(_DMARC_UNIT)
    result = infer(
        net,  # type: ignore[arg-type]
        observed_slugs=slugs,
        observed_signals=signals,
        priors_override={},
        masked_units=masked_units,
    )
    for p in result.posteriors:
        if p.name == _POLICY_NODE:
            return float(p.posterior)
    return None


def reference_label_email_policy(
    dmarc_policy: str | None,
    degraded_sources: Collection[str] = (),
) -> int | None:
    """The authoritative enforcing/not label from a domain's DMARC policy.

    Returns 1 when the published policy is enforcing (reject / quarantine),
    and 0 when it is explicitly non-enforcing (none) or a successful lookup
    observed no record. Returns None when a DMARC-relevant collection channel
    failed or a nonempty parsed value is unrecognized. This separates observed
    absence from missing observation.
    """
    status = SourceStatus.from_degraded_sources(degraded_sources)
    if status.channel_unavailable("dmarc"):
        return None
    if dmarc_policy is None:
        return 0
    policy = dmarc_policy.strip().lower()
    if policy in _ENFORCING_POLICIES:
        return 1
    if policy in _NON_ENFORCING_POLICIES:
        return 0
    return None


def wilson_interval(successes: int, n: int, z: float = 1.2816) -> tuple[float, float]:
    """Wilson score diagnostic range for a binomial row proportion.

    Preferred over the normal approximation for iid binomial samples near 0 or
    1 and for small n. In these selected validation cohorts, row independence
    and population sampling are not established, so the returned range is a
    naive iid diagnostic with no population-coverage interpretation. Default
    ``z`` is the 80% two-sided quantile; pass 1.96 for 95%.
    """
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z * math.sqrt(p * (1.0 - p) / n + z2 / (4 * n * n))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


@dataclass(frozen=True)
class CalibrationRecord:
    """One domain's posterior and its reference label for a node.

    Carries no apex: the domain identity is dropped at collection time so
    nothing downstream can leak it.
    """

    posterior: float
    label: int


@dataclass(frozen=True)
class CalibrationPair:
    """One domain's full and held-out-residual records (no apex).

    ``full`` is the shipped posterior (DMARC evidence included, so the label
    overlaps the input); ``held_out`` is the residual posterior with the
    ``dmarc_policy`` unit masked, so predictor and label are disjoint.
    """

    full: CalibrationRecord
    held_out: CalibrationRecord


def mean_log_score(records: list[CalibrationRecord], clamp: float = 1e-6) -> float:
    """Mean negative log-likelihood of the labels under the posteriors.

    The proper scoring rule CAL9 asks the memos to lead with (lower is
    better; a perfectly-confident correct predictor scores ~0, the
    always-0.5 predictor scores ln 2 ~ 0.693). Posteriors are clamped away
    from {0, 1} so a single confidently-wrong record cannot return inf —
    the clamp is reported behaviour, not hidden: at the default 1e-6 a
    confident miss costs ~13.8 nats, which dominates the mean exactly as a
    proper scoring rule should.
    """
    if not records:
        return 0.0
    total = 0.0
    for r in records:
        p = min(max(r.posterior, clamp), 1.0 - clamp)
        total += -math.log(p if r.label == 1 else 1.0 - p)
    return total / len(records)


def calibration_summary(records: list[CalibrationRecord], bins: int = 10) -> dict[str, object]:
    """Aggregate calibration of the posteriors against the reference labels.

    Returns Brier, the mean log-score (the proper scoring rule, per CAL9),
    ECE, the reliability table, the agreement rate (point estimate
    ``posterior >= 0.5`` versus the label) with a naive iid Wilson diagnostic
    range, and the base rate. The ECE bootstrap likewise resamples rows as iid.
    Neither range has a coverage interpretation for a selected, dependent
    cohort. All output is aggregate; no per-record data.
    """
    n = len(records)
    if n == 0:
        return {"n": 0}
    preds = [r.posterior for r in records]
    labels = [r.label for r in records]
    table = _reliability_table(preds, labels, bins=bins)
    mean_bin_ece = bootstrap_mean_confidence_ece(
        preds,
        labels,
        bins=bins,
        samples=_ECE_BOOTSTRAP_SAMPLES,
    )
    agree = sum(1 for r in records if (r.posterior >= 0.5) == bool(r.label))
    wlo, whi = wilson_interval(agree, n)
    return {
        "n": n,
        "base_rate_enforcing": round(sum(labels) / n, 4),
        "brier": round(_brier(preds, labels), 4),
        "log_score": round(mean_log_score(records), 4),
        "ece": round(_expected_calibration_error(table, n), 4),
        "ece_equal_mass": round(mean_bin_ece.estimate, 4),
        "ece_equal_mass_ci80": (round(mean_bin_ece.ci_low, 4), round(mean_bin_ece.ci_high, 4)),
        "agreement_rate": round(agree / n, 4),
        "agreement_wilson80": (round(wlo, 4), round(whi, 4)),
        "interval_interpretation": {
            "ece_equal_mass_ci80": "naive iid row-bootstrap diagnostic range; no coverage claim",
            "agreement_wilson80": "naive iid Wilson diagnostic range; no population-coverage claim",
        },
        "reliability": [
            {"bin_low": round(low, 2), "bin_high": round(high, 2), "enforcing_rate": round(freq, 4), "count": count}
            for (low, high, freq, count) in table
        ],
        "reliability_equal_mass": [
            {
                "bin_low": round(row.bin_low, 4),
                "bin_high": round(row.bin_high, 4),
                "mean_confidence": round(row.mean_confidence, 4),
                "enforcing_rate": round(row.empirical_rate, 4),
                "count": row.count,
            }
            for row in equal_mass_reliability_bins(preds, labels, bins=bins)
        ],
    }


def stratified_summary(
    strata: dict[str, list[CalibrationRecord]], min_cell: int = 10, bins: int = 10
) -> dict[str, object]:
    """Per-stratum diagnostics plus a descriptive pooled total.

    Each stratum (e.g. a vertical) reports its own ``calibration_summary``.
    A stratum with fewer than ``min_cell`` usable records is suppressed to a
    ``{"n": n, "suppressed": True}`` stub rather than reported, the
    small-cell discipline (a calibration number on a handful of domains is
    noise, and small cells are also more identifying). Strata are keyed by a
    generic label only; the keys never carry an apex.
    """
    out_strata: dict[str, object] = {}
    pooled: list[CalibrationRecord] = []
    for name in sorted(strata):
        records = strata[name]
        pooled.extend(records)
        if len(records) < min_cell:
            out_strata[name] = {"n": len(records), "suppressed": True}
        else:
            out_strata[name] = calibration_summary(records, bins=bins)
    return {"strata": out_strata, "pooled": calibration_summary(pooled, bins=bins), "min_cell": min_cell}


async def _collect_one(
    domain: str, *, timeout: float, skip_ct: bool, sem: asyncio.Semaphore
) -> CalibrationPair | None:
    """Resolve one domain, infer, and pair both posteriors with the
    reference label. Returns None when the DMARC observation failed or its
    nonempty parsed policy is unrecognized.

    The apex is used only to resolve; it is never returned or logged.
    """
    from recon_tool.bayesian import infer_from_tenant_info, signals_from_tenant_info
    from recon_tool.resolver import resolve_tenant

    async with sem:
        try:
            info, _results = await resolve_tenant(domain, timeout=timeout, skip_ct=skip_ct)
        except Exception:  # one domain failing must not abort the sweep
            return None
    label = reference_label_email_policy(
        getattr(info, "dmarc_policy", None),
        getattr(info, "degraded_sources", ()) or (),
    )
    if label is None:
        return None
    posteriors = {
        p.name: p for p in infer_from_tenant_info(info, priors_override={}).posteriors
    }
    node = posteriors.get(_POLICY_NODE)
    if node is None:
        return None
    residual = held_out_policy_posterior(
        set(getattr(info, "slugs", ()) or ()),
        signals_from_tenant_info(info),
        degraded_sources=getattr(info, "degraded_sources", ()) or (),
    )
    if residual is None:
        return None
    return CalibrationPair(
        full=CalibrationRecord(posterior=float(node.posterior), label=label),
        held_out=CalibrationRecord(posterior=residual, label=label),
    )


async def collect(
    domains: list[str], *, timeout: float, skip_ct: bool, concurrency: int, label: str = "resolving"
) -> list[CalibrationPair]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [_collect_one(d, timeout=timeout, skip_ct=skip_ct, sem=sem) for d in domains]
    results = await gather_with_progress(tasks, label=label)
    return [r for r in results if r is not None]


def _read_domains(path: Path) -> list[str]:
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _print_summary(summary: dict[str, object], header: str) -> None:
    print(f"\n{header} (n={summary['n']} with an observed DMARC label)")
    print(f"  base rate enforcing:   {summary['base_rate_enforcing']}")
    print(f"  log score (proper):    {summary['log_score']}")
    print(f"  Brier:                 {summary['brier']}")
    print(f"  ECE fixed-width:       {summary['ece']}")
    print(
        f"  ECE tie-preserving:    {summary['ece_equal_mass']}  "
        f"naive-iid bootstrap range80 {summary['ece_equal_mass_ci80']}"
    )
    print(
        f"  agreement rate:        {summary['agreement_rate']}  "
        f"naive-iid Wilson range80 {summary['agreement_wilson80']}"
    )
    print("  reliability (posterior bin -> empirical enforcing rate):")
    for row in summary["reliability"]:  # type: ignore[attr-defined]
        print(f"    [{row['bin_low']:.2f}, {row['bin_high']:.2f})  rate {row['enforcing_rate']:.3f}  n {row['count']}")


_TRAILER = (
    "\nTwo constructions. The full-score block is selected-list corroboration with\n"
    "predictor-label overlap on the DMARC input. The held-out block masks the\n"
    "dmarc_policy evidence unit, making predictor and label disjoint inside recon's\n"
    "computation. It remains a descriptive residual evaluation on the selected\n"
    "corpus, not proof of independent observations or population calibration.\n"
    "Bootstrap and Wilson ranges use naive iid rows and have no coverage\n"
    "interpretation for this selected cohort.\n"
    "See docs/statistical-assurance.md."
)


def _print_both(pairs: list[CalibrationPair], *, bins: int) -> None:
    full = calibration_summary([p.full for p in pairs], bins=bins)
    _print_summary(full, "Email-policy full score versus DMARC (overlapping corroboration)")
    held_out = calibration_summary([p.held_out for p in pairs], bins=bins)
    _print_summary(held_out, "Predictor-disjoint residual (dmarc_policy masked)")


def _run_single(path: Path, *, bins: int, concurrency: int, timeout: float, as_json: bool = False) -> int:
    domains = _read_domains(path)
    if not as_json:
        print(f"Resolving {len(domains)} domains against the DMARC record (aggregates only, no apex printed)...")
    # CT is skipped throughout: the policy node's evidence is DNS-only (DMARC /
    # SPF / MTA-STS), so a CT pass would add cost without changing the posterior.
    pairs = asyncio.run(collect(domains, timeout=timeout, skip_ct=True, concurrency=concurrency))
    if as_json:
        # Structured output for downstream cross-list agreement checks and the
        # PV2 drift loop. Aggregates only, same as the text path.
        print(
            json.dumps(
                {
                    "mode": "single",
                    "n": len(pairs),
                    "full": calibration_summary([p.full for p in pairs], bins=bins) if pairs else {"n": 0},
                    "held_out": calibration_summary([p.held_out for p in pairs], bins=bins) if pairs else {"n": 0},
                },
                indent=2,
            )
        )
        return 0
    if not pairs:
        print("No domains carried a DMARC reference label; nothing to calibrate.")
        return 0
    _print_both(pairs, bins=bins)
    print(_TRAILER)
    return 0


def _print_strata_table(result: dict[str, object], *, min_cell: int, title: str) -> None:
    print(f"\n{title} (cells with n < {min_cell} suppressed)")
    print(f"  {'stratum':<28}{'n':>5}{'ECE':>8}{'agree':>8}{'base':>8}")
    print("  " + "-" * 57)
    for name, s in result["strata"].items():  # type: ignore[attr-defined]
        if s.get("suppressed"):
            print(f"  {name:<28}{s['n']:>5}{'  suppressed':>24}")
        else:
            print(f"  {name:<28}{s['n']:>5}{s['ece']:>8.3f}{s['agreement_rate']:>8.3f}{s['base_rate_enforcing']:>8.2f}")


def _run_stratified(
    directory: Path, *, bins: int, concurrency: int, timeout: float, min_cell: int, as_json: bool = False
) -> int:
    files = sorted(directory.glob("*.txt"))
    if not files:
        print(f"FAIL: no .txt domain lists in {directory}")
        return 1
    if not as_json:
        print(f"Calibrating per stratum over {len(files)} lists (aggregates only, no apex printed)...")
    strata_pairs: dict[str, list[CalibrationPair]] = {}
    for f in files:
        pairs = asyncio.run(
            collect(_read_domains(f), timeout=timeout, skip_ct=True, concurrency=concurrency, label=f.stem)
        )
        strata_pairs[f.stem] = pairs
    full_result = stratified_summary(
        {name: [p.full for p in pairs] for name, pairs in strata_pairs.items()}, min_cell=min_cell, bins=bins
    )
    held_out_result = stratified_summary(
        {name: [p.held_out for p in pairs] for name, pairs in strata_pairs.items()}, min_cell=min_cell, bins=bins
    )
    if as_json:
        print(json.dumps({"mode": "stratified", "full": full_result, "held_out": held_out_result}, indent=2))
        return 0
    _print_strata_table(full_result, min_cell=min_cell, title="Per-stratum email-policy calibration (full posterior)")
    _print_summary(full_result["pooled"], "Descriptive pool across strata (full score)")  # type: ignore[arg-type]
    _print_strata_table(
        held_out_result, min_cell=min_cell, title="Per-stratum held-out residual (dmarc_policy masked)"
    )
    _print_summary(held_out_result["pooled"], "Descriptive pool across strata (predictor-disjoint residual)")  # type: ignore[arg-type]
    print(_TRAILER)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare the email-policy score with the DMARC declaration.")
    parser.add_argument("domains", type=Path, nargs="?", help="File with one apex per line (gitignored; local).")
    parser.add_argument(
        "--stratify-dir", type=Path, default=None, help="Directory of per-stratum *.txt lists; calibrate each."
    )
    parser.add_argument(
        "--min-cell", type=int, default=10, help="Suppress strata below this many records (default 10)."
    )
    parser.add_argument("--bins", type=int, default=10, help="Reliability bins (default 10).")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent resolves (default 5).")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-domain resolve timeout seconds.")
    parser.add_argument(
        "--json", action="store_true", help="Emit aggregates as JSON (for cross-list comparison / PV2 drift)."
    )
    args = parser.parse_args(argv)

    if args.stratify_dir is not None:
        if not args.stratify_dir.is_dir():
            print(f"FAIL: stratify directory not found: {args.stratify_dir}")
            return 1
        return _run_stratified(
            args.stratify_dir,
            bins=args.bins,
            concurrency=args.concurrency,
            timeout=args.timeout,
            min_cell=args.min_cell,
            as_json=args.json,
        )
    if args.domains is None or not args.domains.is_file():
        print("FAIL: provide a domains file or --stratify-dir DIR")
        return 1
    return _run_single(
        args.domains, bins=args.bins, concurrency=args.concurrency, timeout=args.timeout, as_json=args.json
    )


if __name__ == "__main__":
    raise SystemExit(main())
