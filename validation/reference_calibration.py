"""CAL3 / CAL4: calibrate a posterior against a public reference (the record
that is its own ground truth).

Most recon claims have no passive ground truth (a hardened operator can
hide the indicators, so the absence is adversarially missing; see
correlation.md section 4.3 and docs/statistical-assurance.md). One node
is the exception. ``email_security_policy_enforcing`` infers a
probability that a domain's email-authentication policy is enforcing,
and the authoritative definition of "enforcing" is a public declaration
anyone can read: a DMARC policy of ``reject`` or ``quarantine`` (RFC
7489). The published DMARC record is its own ground truth, so it is a
known-truth reference the posterior can be calibrated against, not merely
a self-consistency check.

What this measures, and what it does not. The reference label here comes
from an authoritative external definition (the published DMARC policy
level), not from recon's own posterior, so this is firmer than the
near-tautological deterministic-vs-Bayesian consistency check (tier 2 in
the statistical-assurance dossier). It is not the fully-independent
ground truth of an ideal frequentist study, because the node's own
evidence includes the DMARC signal, so the posterior and the reference
overlap on input. What it does test honestly: whether recon's combined
multi-signal posterior (DMARC plus strict SPF plus MTA-STS, under the
node's definition) is calibrated against the authoritative DMARC-only
definition. Where recon over-weights SPF or MTA-STS and reports a high
posterior on a domain whose DMARC is ``p=none``, the reference catches it.

Why calibration and not interval coverage. The reference label is binary
(enforcing or not), and a credible interval is for the probability, so
"does the 80% interval contain the label" is a category mismatch.
Calibration against a binary label is the measurable thing: bin the
posteriors and check the empirical enforcing-rate in each bin against
the posterior (reliability / ECE), and score the posterior against the
label (Brier). Frequentist interval coverage in the CAL3 sense needs a
probability truth or repeated trials per evidence pattern, which the
synthetic perturbation harness supplies (validation/interval_coverage.py);
this harness supplies the real-record calibration that the synthetic one
cannot.

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
"""

# Reuses the tested calibration internals (_brier / _reliability_table /
# _expected_calibration_error) from synthetic_calibration, the single source for
# this math; legitimate cross-harness reuse, the same allowance the other
# validation harnesses take.
# pyright: reportPrivateUsage=false
from __future__ import annotations

import argparse
import asyncio
import math
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from validation.synthetic_calibration import (  # noqa: E402
    _brier,
    _expected_calibration_error,
    _reliability_table,
)

# The node this harness calibrates and the policy levels that count as the
# authoritative "enforcing" ground truth (RFC 7489: reject and quarantine
# are enforcing; none is not).
_POLICY_NODE = "email_security_policy_enforcing"
_ENFORCING_POLICIES = frozenset({"reject", "quarantine"})
_NON_ENFORCING_POLICIES = frozenset({"none"})


def reference_label_email_policy(dmarc_policy: str | None) -> int | None:
    """The authoritative enforcing/not label from a domain's DMARC policy.

    Returns 1 when the published policy is enforcing (reject / quarantine),
    0 when it is explicitly non-enforcing (none), and None when no DMARC
    record was observed, in which case the domain carries no reference
    truth and is excluded from the calibration rather than guessed.
    """
    if dmarc_policy is None:
        return None
    policy = dmarc_policy.strip().lower()
    if policy in _ENFORCING_POLICIES:
        return 1
    if policy in _NON_ENFORCING_POLICIES:
        return 0
    return None


def wilson_interval(successes: int, n: int, z: float = 1.2816) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Preferred over the normal approximation for rates near 0 or 1 and for
    small n. Default ``z`` is the 80% two-sided quantile, matching recon's
    80% interval convention; pass 1.96 for 95%.
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


def calibration_summary(records: list[CalibrationRecord], bins: int = 10) -> dict[str, object]:
    """Aggregate calibration of the posteriors against the reference labels.

    Returns Brier, ECE, the reliability table, the agreement rate (point
    estimate ``posterior >= 0.5`` versus the label) with an 80% Wilson
    interval, and the base rate. All aggregate; no per-record data.
    """
    n = len(records)
    if n == 0:
        return {"n": 0}
    preds = [r.posterior for r in records]
    labels = [r.label for r in records]
    table = _reliability_table(preds, labels, bins=bins)
    agree = sum(1 for r in records if (r.posterior >= 0.5) == bool(r.label))
    wlo, whi = wilson_interval(agree, n)
    return {
        "n": n,
        "base_rate_enforcing": round(sum(labels) / n, 4),
        "brier": round(_brier(preds, labels), 4),
        "ece": round(_expected_calibration_error(table, n), 4),
        "agreement_rate": round(agree / n, 4),
        "agreement_wilson80": (round(wlo, 4), round(whi, 4)),
        "reliability": [
            {"bin_low": round(low, 2), "bin_high": round(high, 2), "enforcing_rate": round(freq, 4), "count": count}
            for (low, high, freq, count) in table
        ],
    }


async def _collect_one(
    domain: str, *, timeout: float, skip_ct: bool, sem: asyncio.Semaphore
) -> CalibrationRecord | None:
    """Resolve one domain, infer, and pair the policy posterior with the
    reference label. Returns None when the domain has no DMARC reference truth.

    The apex is used only to resolve; it is never returned or logged.
    """
    from recon_tool.bayesian import infer_from_tenant_info
    from recon_tool.resolver import resolve_tenant

    async with sem:
        try:
            info, _results = await resolve_tenant(domain, timeout=timeout, skip_ct=skip_ct)
        except Exception:  # one domain failing must not abort the sweep
            return None
    label = reference_label_email_policy(getattr(info, "dmarc_policy", None))
    if label is None:
        return None
    posteriors = {p.name: p for p in infer_from_tenant_info(info).posteriors}
    node = posteriors.get(_POLICY_NODE)
    if node is None:
        return None
    return CalibrationRecord(posterior=float(node.posterior), label=label)


async def collect(domains: list[str], *, timeout: float, skip_ct: bool, concurrency: int) -> list[CalibrationRecord]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [_collect_one(d, timeout=timeout, skip_ct=skip_ct, sem=sem) for d in domains]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


def _read_domains(path: Path) -> list[str]:
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Calibrate the email-policy posterior against the DMARC record.")
    parser.add_argument("domains", type=Path, help="File with one apex per line (gitignored; stays local).")
    parser.add_argument("--bins", type=int, default=10, help="Reliability bins (default 10).")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent resolves (default 5).")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-domain resolve timeout seconds.")
    args = parser.parse_args(argv)
    if not args.domains.is_file():
        print(f"FAIL: domains file not found: {args.domains}")
        return 1

    domains = _read_domains(args.domains)
    print(f"Resolving {len(domains)} domains against the DMARC record (aggregates only, no apex printed)...")
    # CT is skipped throughout: the policy node's evidence is DNS-only (DMARC /
    # SPF / MTA-STS), so a CT pass would add cost without changing the posterior.
    records = asyncio.run(collect(domains, timeout=args.timeout, skip_ct=True, concurrency=args.concurrency))
    summary = calibration_summary(records, bins=args.bins)
    if summary["n"] == 0:
        print("No domains carried a DMARC reference label; nothing to calibrate.")
        return 0

    print(f"\nEmail-policy node calibrated against the DMARC record (n={summary['n']} with a published policy)")
    print(f"  base rate enforcing:   {summary['base_rate_enforcing']}")
    print(f"  Brier:                 {summary['brier']}")
    print(f"  ECE:                   {summary['ece']}")
    print(f"  agreement rate:        {summary['agreement_rate']}  Wilson80 {summary['agreement_wilson80']}")
    print("  reliability (posterior bin -> empirical enforcing rate):")
    for row in summary["reliability"]:  # type: ignore[attr-defined]
        print(f"    [{row['bin_low']:.2f}, {row['bin_high']:.2f})  rate {row['enforcing_rate']:.3f}  n {row['count']}")
    print("\nThis is reference-anchored calibration (the label is the authoritative DMARC")
    print("policy, an external definition), firmer than tier-2 consistency but not the")
    print("fully-independent ground truth of an ideal study; see docs/statistical-assurance.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
