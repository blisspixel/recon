"""Tenancy reference calibration against the provider identity endpoints.

The reference-calibration harness (validation/reference_calibration.py)
covers the one *public-declaration* node, the DMARC email policy. This
harness covers the *provider-attested* tenancy claims: whether a domain has
a Microsoft 365 / Entra tenant is answered by Microsoft's own
unauthenticated identity endpoints, keyed on the domain, which the operator
does not control and cannot suppress without actually leaving the tenant
(correlation.md section 5.1, the provenance and manipulation spectrum).
That makes the endpoint answer a useful related-channel reference for the
DNS-driven inference. The result is corroboration rather than fully independent
calibration because both channels share tenant provisioning. This is the open tenancy extension the
statistical-assurance dossier names.

The channel split, which is the whole design. The provider endpoints also
*feed* the m365_tenant node (the OIDC and GetUserRealm sources fire the
``microsoft365`` slug, and ``federated_sso_hub`` derives from the
endpoint-reported auth type), so calibrating the shipped full posterior
against the endpoint label would be largely circular. Masking does not
help here the way it does for the policy node: the node's entire direct
evidence is one correlation group, so a masked posterior collapses to the
prior. Instead the predictor and label are split by *observation channel*:

- **Predictor**: the tenancy posterior computed from the DNS channel alone
  (the ``dns_records`` source re-merged by itself: MX / SPF / TXT / CNAME
  fingerprints; no identity-endpoint input, and no ``federated_sso_hub``
  signal, since the auth type is endpoint-derived).
- **Label**: the provider attestation. Positive when the OIDC discovery
  endpoint resolves the domain to a tenant ID, or GetUserRealm reports
  NameSpaceType Managed/Federated. Negative when the OIDC endpoint returns
  HTTP 400 (the tenant-not-found response for a well-formed domain) or
  GetUserRealm reports NameSpaceType Unknown. Domains where the channels
  conflict, or where neither endpoint gave an authoritative answer, carry
  no label and are excluded (and counted, so the exclusion is visible).

The full-pipeline posterior is also reported against the same label, but
explicitly as a *consistency* number (CAL1 discipline): the endpoint
evidence is an input to it, so its agreement is near-definitional. The
DNS-only block is the corroboration result.

Google Workspace is reported one-sided, not calibrated. recon's Google
identity channel claims Workspace only on an observed federated-IdP
redirect (managed-Workspace detection by response heuristics was removed
as a false-positive source; see sources/google_identity.py), so the
provider channel has no authoritative negative and never attests managed
tenants. A calibration needs both label classes; what the channel honestly
supports is recall-on-attested-positives: among domains the provider
channel attested as federated Workspace, how often did the DNS-only
posterior agree? That number is reported as exactly that, never as
calibration, and the GWS node's dossier tier does not change on its
account.

Assumption, stated. The OIDC negative reads HTTP 400 from
``login.microsoftonline.com/{domain}/.well-known/openid-configuration`` as
tenant-not-found (AADSTS90002). For the well-formed apexes this harness
feeds, that is what 400 means; transient failures surface as non-400
errors and yield no label. The GetUserRealm Unknown channel cross-checks
it, and a disagreement lands in the conflict bucket rather than a label.

Data handling. A run reads real apex domains, so it stays maintainer-local
against the gitignored corpus and emits aggregates only: no apex, no
per-domain row reaches stdout or any committed file
(docs/data-handling-policy.md). The pure functions below carry no target
data and are unit-tested (tests/test_tenancy_reference_calibration.py);
the orchestration is the maintainer-run part.

Run (maintainer-local, network):

    python -m validation.tenancy_reference_calibration domains.txt
    python -m validation.tenancy_reference_calibration domains.txt --stratify-dir validation/corpus-private/by-vertical
    python -m validation.tenancy_reference_calibration domains.txt --json   # structured aggregates

The ``--json`` form emits the same aggregates as a machine-readable object
(``m365_dns_only`` / ``m365_full`` / ``gws_one_sided`` / ``counts`` for the
single mode; ``m365_dns_only`` / ``gws_one_sided`` for ``--stratify-dir``),
for cross-list agreement checks and the PV2 drift loop. Aggregates only,
exactly as the text path; no apex is ever serialized.
"""

# Reuses the tested calibration internals from reference_calibration (the
# single source for the label/Wilson/aggregate math); same allowance the
# other validation harnesses take.
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.models import SourceResult  # noqa: E402
from validation.progress import gather_with_progress  # noqa: E402
from validation.reference_calibration import (  # noqa: E402
    CalibrationRecord,
    calibration_summary,
    stratified_summary,
    wilson_interval,
)

_M365_NODE = "m365_tenant"
_GWS_NODE = "google_workspace_tenant"

# Source names, as emitted by the corresponding SourceResult.source_name.
_DNS_SOURCE = "dns_records"
_OIDC_SOURCE = "oidc_discovery"
_REALM_SOURCE = "user_realm"
_GOOGLE_IDENTITY_SOURCE = "google_identity"

# GetUserRealm NameSpaceType values that attest an M365/Entra tenant, and the
# value that attests its absence.
_REALM_POSITIVE = frozenset({"managed", "federated"})
_REALM_NEGATIVE = "unknown"

# The OIDC source surfaces HTTP failures as "HTTP {status} from OIDC discovery
# endpoint"; 400 is the documented tenant-not-found response for a well-formed
# domain (AADSTS90002).
_OIDC_NOT_FOUND_PREFIX = "HTTP 400"

# Label dispositions.
POSITIVE = "positive"
NEGATIVE = "negative"
UNLABELED = "unlabeled"
CONFLICT = "conflict"


def m365_reference_label(
    oidc_tenant_id: str | None,
    oidc_error: str | None,
    realm_namespace: str | None,
) -> str:
    """The M365 tenancy disposition from the two provider endpoints.

    Positive attestations: a tenant ID extracted from the OIDC discovery
    document, or a GetUserRealm NameSpaceType of Managed/Federated.
    Negative attestations: the OIDC endpoint's HTTP 400 (tenant not found
    for a well-formed domain), or NameSpaceType Unknown. Any positive
    together with any negative is a CONFLICT (excluded and counted, never
    guessed); neither is UNLABELED.
    """
    namespace = (realm_namespace or "").strip().lower()
    positive = bool(oidc_tenant_id) or namespace in _REALM_POSITIVE
    negative = bool(oidc_error and oidc_error.startswith(_OIDC_NOT_FOUND_PREFIX)) or namespace == _REALM_NEGATIVE
    if positive and negative:
        return CONFLICT
    if positive:
        return POSITIVE
    if negative:
        return NEGATIVE
    return UNLABELED


def gws_attested_federated(google_auth_type: str | None) -> bool:
    """True when the Google identity channel attested a federated Workspace
    tenant — the only attestation that channel can make (one-sided)."""
    return (google_auth_type or "").strip().lower() == "federated"


def dns_only_tenancy_posteriors(
    results: list[SourceResult],
    queried_domain: str,
) -> tuple[float, float] | None:
    """(m365, gws) posteriors from the DNS channel alone.

    Re-merges only the successful ``dns_records`` SourceResults and runs
    inference on that merge, so no identity-endpoint observation (slug or
    derived signal) reaches the predictor. A DNS result with no detections
    merges to a sparse TenantInfo and yields near-prior posteriors, which is
    the correct predictor for a no-footprint domain — those records must
    stay in the calibration or the negative stratum is biased away. Returns
    None when the DNS channel itself failed (counted by the caller).
    Inference is pinned to the committed priors so a maintainer's local
    ``~/.recon/priors.yaml`` cannot change a recorded validation result.
    """
    from recon_tool.bayesian import infer_from_tenant_info
    from recon_tool.merger import merge_results

    dns = [
        r
        for r in results
        if getattr(r, "source_name", "") == _DNS_SOURCE and getattr(r, "error", None) is None
    ]
    if not dns:
        return None
    try:
        info = merge_results(list(dns), queried_domain)
    except Exception:
        return None
    result = infer_from_tenant_info(info, priors_override={})
    posteriors = {p.name: float(p.posterior) for p in result.posteriors}
    m365 = posteriors.get(_M365_NODE)
    gws = posteriors.get(_GWS_NODE)
    if m365 is None or gws is None:
        return None
    return (m365, gws)


def percentile(values: list[float], q: float) -> float:
    """Linear-interpolation percentile of ``values`` (q in [0, 1])."""
    if not values:
        raise ValueError("percentile of empty list")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = q * (len(ordered) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    frac = pos - lo
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac


def one_sided_recall_summary(posteriors: list[float], threshold: float = 0.5) -> dict[str, object]:
    """Recall-on-attested-positives for the one-sided GWS check.

    Among domains the provider channel attested (label 1 by construction —
    there is no negative class), the fraction whose posterior clears the
    decision threshold, with a naive iid 80% Wilson diagnostic range, plus
    posterior quartiles. The selected rows are not established to be iid, so
    the range has no population-coverage interpretation. Deliberately NOT a
    calibration summary: with one label class, ECE/Brier would only restate the
    mean posterior.
    """
    n = len(posteriors)
    if n == 0:
        return {"n": 0}
    hits = sum(1 for p in posteriors if p >= threshold)
    wlo, whi = wilson_interval(hits, n)
    return {
        "n": n,
        "threshold": threshold,
        "recall": round(hits / n, 4),
        "recall_wilson80": (round(wlo, 4), round(whi, 4)),
        "interval_interpretation": "naive iid Wilson diagnostic range; no population-coverage claim",
        "posterior_quartiles": (
            round(percentile(posteriors, 0.25), 4),
            round(percentile(posteriors, 0.50), 4),
            round(percentile(posteriors, 0.75), 4),
        ),
    }


@dataclass(frozen=True)
class TenancyRecord:
    """One domain's tenancy posteriors and label dispositions (no apex)."""

    m365_disposition: str
    m365_dns_only: float | None
    m365_full: float | None
    gws_attested: bool
    gws_dns_only: float | None


@dataclass(frozen=True)
class TenancyCounts:
    """Aggregate disposition counts for one collection sweep."""

    resolved: int = 0
    resolve_failed: int = 0
    no_dns_channel: int = 0
    m365_positive: int = 0
    m365_negative: int = 0
    m365_unlabeled: int = 0
    m365_conflict: int = 0
    gws_attested: int = 0


async def _collect_one(
    domain: str, *, timeout: float, skip_ct: bool, sem: asyncio.Semaphore
) -> TenancyRecord | None:
    """Resolve one domain and derive its tenancy record.

    The apex is used only to resolve; it is never returned or logged.
    """
    from recon_tool.bayesian import infer_from_tenant_info
    from recon_tool.resolver import resolve_tenant

    async with sem:
        try:
            info, results = await resolve_tenant(domain, timeout=timeout, skip_ct=skip_ct)
        except Exception:  # one domain failing must not abort the sweep
            return None

    by_name: dict[str, object] = {}
    for r in results:
        name = getattr(r, "source_name", "")
        if name and name not in by_name:
            by_name[name] = r

    oidc = by_name.get(_OIDC_SOURCE)
    realm = by_name.get(_REALM_SOURCE)
    gid = by_name.get(_GOOGLE_IDENTITY_SOURCE)

    disposition = m365_reference_label(
        getattr(oidc, "tenant_id", None) if oidc is not None else None,
        getattr(oidc, "error", None) if oidc is not None else None,
        getattr(realm, "auth_type", None) if realm is not None else None,
    )
    attested = gws_attested_federated(getattr(gid, "google_auth_type", None) if gid is not None else None)

    dns_pair = dns_only_tenancy_posteriors(list(results), domain)
    full = {
        p.name: float(p.posterior)
        for p in infer_from_tenant_info(info, priors_override={}).posteriors
    }

    return TenancyRecord(
        m365_disposition=disposition,
        m365_dns_only=dns_pair[0] if dns_pair is not None else None,
        m365_full=full.get(_M365_NODE),
        gws_attested=attested,
        gws_dns_only=dns_pair[1] if dns_pair is not None else None,
    )


async def collect(
    domains: list[str], *, timeout: float, skip_ct: bool, concurrency: int, label: str = "resolving"
) -> tuple[list[TenancyRecord], TenancyCounts]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [_collect_one(d, timeout=timeout, skip_ct=skip_ct, sem=sem) for d in domains]
    raw = await gather_with_progress(tasks, label=label)
    records = [r for r in raw if r is not None]
    counts = TenancyCounts(
        resolved=len(records),
        resolve_failed=len(raw) - len(records),
        no_dns_channel=sum(1 for r in records if r.m365_dns_only is None),
        m365_positive=sum(1 for r in records if r.m365_disposition == POSITIVE),
        m365_negative=sum(1 for r in records if r.m365_disposition == NEGATIVE),
        m365_unlabeled=sum(1 for r in records if r.m365_disposition == UNLABELED),
        m365_conflict=sum(1 for r in records if r.m365_disposition == CONFLICT),
        gws_attested=sum(1 for r in records if r.gws_attested),
    )
    return records, counts


def m365_calibration_records(records: list[TenancyRecord], *, full_pipeline: bool) -> list[CalibrationRecord]:
    """Labeled (posterior, label) pairs for the M365 node.

    ``full_pipeline=False`` selects the DNS-only predictor (the
    corroboration construction); True selects the shipped full posterior
    (the consistency check, label overlaps input).
    """
    out: list[CalibrationRecord] = []
    for r in records:
        if r.m365_disposition not in (POSITIVE, NEGATIVE):
            continue
        posterior = r.m365_full if full_pipeline else r.m365_dns_only
        if posterior is None:
            continue
        out.append(CalibrationRecord(posterior=posterior, label=1 if r.m365_disposition == POSITIVE else 0))
    return out


def gws_attested_posteriors(records: list[TenancyRecord]) -> list[float]:
    return [r.gws_dns_only for r in records if r.gws_attested and r.gws_dns_only is not None]


def _read_domains(path: Path) -> list[str]:
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _print_summary(summary: dict[str, object], header: str) -> None:
    print(f"\n{header} (n={summary['n']} with a provider label)")
    print(f"  base rate tenant:      {summary['base_rate_enforcing']}")
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
    print("  reliability (posterior bin -> empirical tenant rate):")
    for row in summary["reliability"]:  # type: ignore[attr-defined]
        print(f"    [{row['bin_low']:.2f}, {row['bin_high']:.2f})  rate {row['enforcing_rate']:.3f}  n {row['count']}")


def _print_counts(counts: TenancyCounts) -> None:
    print("\nDispositions (aggregate):")
    print(
        f"  resolved {counts.resolved}, resolve-failed {counts.resolve_failed}, "
        f"no-DNS-channel {counts.no_dns_channel}"
    )
    print(
        f"  M365 label: positive {counts.m365_positive}, negative {counts.m365_negative}, "
        f"unlabeled {counts.m365_unlabeled}, conflict {counts.m365_conflict}"
    )
    print(f"  GWS attested (federated redirect): {counts.gws_attested}")


def _print_gws_block(summary: dict[str, object]) -> None:
    print("\nGWS one-sided check (recall on provider-attested federated tenants; NOT calibration)")
    if summary["n"] == 0:
        print("  no attested-federated domains in this set")
        return
    print(f"  n attested:            {summary['n']}")
    print(
        f"  recall @ {summary['threshold']}:          {summary['recall']}  "
        f"naive-iid Wilson range80 {summary['recall_wilson80']}"
    )
    q1, q2, q3 = summary["posterior_quartiles"]  # type: ignore[misc]
    print(f"  DNS-only posterior quartiles: p25 {q1}  p50 {q2}  p75 {q3}")


_TRAILER = (
    "\nThe DNS-only block is the corroboration result: predictor (DNS channel) and\n"
    "label (provider attestation) are disjoint observation channels. The\n"
    "full-pipeline block is a consistency check only (the endpoints feed it), per\n"
    "CAL1. The GWS block is one-sided by the nature of the channel (no managed\n"
    "detection, no authoritative negative) and is never a calibration claim. See\n"
    "docs/statistical-assurance.md and validation/reference-calibration.md.\n"
    "Bootstrap and Wilson ranges use naive iid rows and have no coverage\n"
    "interpretation for this selected cohort."
)


def _run_single(path: Path, *, bins: int, concurrency: int, timeout: float, as_json: bool = False) -> int:
    domains = _read_domains(path)
    if not as_json:
        print(f"Resolving {len(domains)} domains against the provider endpoints (aggregates only, no apex printed)...")
    # CT is skipped: the tenancy nodes' evidence is DNS/endpoint-driven, and
    # the DNS-only predictor uses the dns_records source alone.
    records, counts = asyncio.run(collect(domains, timeout=timeout, skip_ct=True, concurrency=concurrency))
    dns_records_cal = m365_calibration_records(records, full_pipeline=False)
    if as_json:
        # Structured aggregates for cross-list agreement checks and PV2 drift.
        # Same numbers as the text path; no apex ever appears. Each block is
        # gated on its OWN record list: the full-pipeline label set is not the
        # DNS-only set (a domain with a failed dns_records source still has a
        # full posterior), so gating m365_full on dns_records_cal would silently
        # drop it to n=0 — the text path computes each independently.
        full_records_cal = m365_calibration_records(records, full_pipeline=True)
        print(
            json.dumps(
                {
                    "mode": "single",
                    "counts": asdict(counts),
                    "m365_dns_only": calibration_summary(dns_records_cal, bins=bins) if dns_records_cal else {"n": 0},
                    "m365_full": calibration_summary(full_records_cal, bins=bins) if full_records_cal else {"n": 0},
                    "gws_one_sided": one_sided_recall_summary(gws_attested_posteriors(records)),
                },
                indent=2,
            )
        )
        return 0
    _print_counts(counts)
    if not dns_records_cal:
        print("\nNo domains carried a provider label with a DNS channel; nothing to calibrate.")
        return 0
    _print_summary(
        calibration_summary(dns_records_cal, bins=bins),
        "M365 tenancy: DNS-only posterior vs provider attestation (corroboration)",
    )
    _print_summary(
        calibration_summary(m365_calibration_records(records, full_pipeline=True), bins=bins),
        "M365 tenancy: full posterior vs provider attestation (consistency only)",
    )
    _print_gws_block(one_sided_recall_summary(gws_attested_posteriors(records)))
    print(_TRAILER)
    return 0


def _run_stratified(
    directory: Path, *, bins: int, concurrency: int, timeout: float, min_cell: int, as_json: bool = False
) -> int:
    files = sorted(directory.glob("*.txt"))
    if not files:
        print(f"FAIL: no .txt domain lists in {directory}")
        return 1
    if not as_json:
        print(f"Calibrating per stratum over {len(files)} lists (aggregates only, no apex printed)...")
    strata: dict[str, list[CalibrationRecord]] = {}
    gws_all: list[float] = []
    for f in files:
        records, _counts = asyncio.run(
            collect(_read_domains(f), timeout=timeout, skip_ct=True, concurrency=concurrency, label=f.stem)
        )
        strata[f.stem] = m365_calibration_records(records, full_pipeline=False)
        gws_all.extend(gws_attested_posteriors(records))
    result = stratified_summary(strata, min_cell=min_cell, bins=bins)
    if as_json:
        print(
            json.dumps(
                {
                    "mode": "stratified",
                    "m365_dns_only": result,
                    "gws_one_sided": one_sided_recall_summary(gws_all),
                },
                indent=2,
            )
        )
        return 0
    print(f"\nPer-stratum M365 DNS-only corroboration (cells with n < {min_cell} suppressed)")
    print(f"  {'stratum':<28}{'n':>5}{'ECE':>8}{'agree':>8}{'base':>8}")
    print("  " + "-" * 57)
    for name, s in result["strata"].items():  # type: ignore[attr-defined]
        if s.get("suppressed"):
            print(f"  {name:<28}{s['n']:>5}{'  suppressed':>24}")
        else:
            print(f"  {name:<28}{s['n']:>5}{s['ece']:>8.3f}{s['agreement_rate']:>8.3f}{s['base_rate_enforcing']:>8.2f}")
    _print_summary(result["pooled"], "Pooled across all strata (DNS-only corroboration)")  # type: ignore[arg-type]
    _print_gws_block(one_sided_recall_summary(gws_all))
    print(_TRAILER)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Calibrate the tenancy posteriors against the provider identity endpoints."
    )
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
