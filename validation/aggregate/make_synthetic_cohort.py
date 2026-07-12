"""Generate a fully synthetic recon-output cohort for the aggregate-state example.

Every domain, brand, and number here is fabricated. The companies are Microsoft's
fictional sample brands (Contoso, Northwind, Fabrikam, and so on); the industry
labels are generic words used only to illustrate caller-supplied grouping; the
distributions are invented to exercise the reducer, not measured from anyone. This
is the only kind of cohort data that may live in the public repo.

Run it to regenerate the fixture and its grouping file:

    python make_synthetic_cohort.py

It writes ``synthetic_cohort.ndjson`` and ``synthetic_groups.csv`` next to itself.
Deterministic (fixed seed), so the worked example in docs/aggregate-state.md stays
reproducible.
"""

from __future__ import annotations

import json
import os
import random
from typing import Any

# Fictional Microsoft sample brands only. No real company appears here.
_BRANDS = [
    "contoso",
    "northwind",
    "fabrikam",
    "adventureworks",
    "wingtiptoys",
    "tailspintoys",
    "proseware",
    "fourthcoffee",
    "litware",
    "alpineskihouse",
    "wideworldimporters",
    "blueyonder",
    "graphicdesigninstitute",
    "lucernepublishing",
    "margiestravel",
    "trey-research",
    "vanarsdel",
    "woodgrovebank",
    "consolidated-messenger",
    "famfields",
    "relecloud",
    "southridgevideo",
    "tailwindtraders",
    "coho-vineyard",
]

# Fabricated per-group profiles: probabilities used only to sample the fixture.
# These are illustrative inventions, not findings.
_PROFILES: dict[str, dict[str, Any]] = {
    "fintech": {
        "m365": 0.85,
        "dmarc_reject": 0.7,
        "dmarc_quarantine": 0.15,
        "gateway": 0.6,
        "mta_sts": 0.45,
        "cloud": {"Azure": 0.5, "AWS": 0.4, None: 0.1},
        "slugs": ["microsoft365", "entra-id", "exchange-online", "okta", "proofpoint", "stripe", "docusign", "splunk"],
        "thin_rate": 0.15,
    },
    "healthcare": {
        "m365": 0.6,
        "dmarc_reject": 0.3,
        "dmarc_quarantine": 0.3,
        "gateway": 0.4,
        "mta_sts": 0.2,
        "cloud": {"Azure": 0.45, "AWS": 0.25, None: 0.3},
        "slugs": ["microsoft365", "exchange-online", "mimecast", "epic-mychart", "servicenow", "zoom"],
        "thin_rate": 0.3,
    },
    "saas": {
        "m365": 0.3,
        "dmarc_reject": 0.65,
        "dmarc_quarantine": 0.2,
        "gateway": 0.2,
        "mta_sts": 0.5,
        "cloud": {"AWS": 0.6, "GCP": 0.3, None: 0.1},
        "slugs": ["google-workspace", "cloudflare", "okta", "fastly", "github", "segment", "datadog", "hubspot"],
        "thin_rate": 0.2,
    },
}


def _pick(rng: random.Random, dist: dict[Any, float]) -> Any:
    r = rng.random()
    cum = 0.0
    for key, p in dist.items():
        cum += p
        if r <= cum:
            return key
    return next(iter(dist))


def _node(
    rng: random.Random, name: str, present: bool, *, declarative: bool = False, thin: bool = False
) -> dict[str, object]:
    """Fabricate one posterior observation consistent with a present/absent fact.

    declarative nodes model CAL14: when absent, the evidence list is empty and the
    node is not sparse (absence is informative). hideable nodes that are absent are
    sparse with an empty evidence list (we could not tell).
    """
    if present and thin:
        post = round(rng.uniform(0.55, 0.7), 3)
        low, high = round(post - rng.uniform(0.18, 0.26), 3), round(post + rng.uniform(0.12, 0.2), 3)
        return {
            "name": name,
            "description": "",
            "posterior": post,
            "interval_low": max(0.0, low),
            "interval_high": min(1.0, high),
            "evidence_used": [f"slug:{name}"],
            "n_eff": round(rng.uniform(1.5, 3.0), 2),
            "sparse": False,
        }
    if present:
        post = round(rng.uniform(0.86, 0.97), 3)
        return {
            "name": name,
            "description": "",
            "posterior": post,
            "interval_low": round(post - rng.uniform(0.05, 0.1), 3),
            "interval_high": min(1.0, round(post + rng.uniform(0.02, 0.05), 3)),
            "evidence_used": [f"slug:{name}", f"signal:{name}"],
            "n_eff": round(rng.uniform(4.0, 8.0), 2),
            "sparse": False,
        }
    if declarative:
        post = round(rng.uniform(0.04, 0.18), 3)
        return {
            "name": name,
            "description": "",
            "posterior": post,
            "interval_low": round(max(0.0, post - 0.04), 3),
            "interval_high": round(post + rng.uniform(0.06, 0.12), 3),
            "evidence_used": [],
            "n_eff": round(rng.uniform(3.0, 6.0), 2),
            "sparse": False,
        }
    # hideable absent: sparse, no evidence
    post = round(rng.uniform(0.1, 0.3), 3)
    return {
        "name": name,
        "description": "",
        "posterior": post,
        "interval_low": round(max(0.0, post - 0.08), 3),
        "interval_high": round(min(1.0, post + rng.uniform(0.25, 0.4)), 3),
        "evidence_used": [],
        "n_eff": round(rng.uniform(0.5, 1.2), 2),
        "sparse": True,
    }


def _record(rng: random.Random, brand: str, group: str) -> dict[str, object]:
    prof = _PROFILES[group]
    domain = f"{brand}.com"
    is_m365 = rng.random() < prof["m365"]
    dmarc = (
        "reject"
        if rng.random() < prof["dmarc_reject"]
        else ("quarantine" if rng.random() < prof["dmarc_quarantine"] else ("none" if rng.random() < 0.5 else None))
    )
    gateway = rng.random() < prof["gateway"]
    mta = "enforce" if rng.random() < prof["mta_sts"] else None
    cloud = _pick(rng, prof["cloud"])
    thin = rng.random() < prof["thin_rate"]
    enforcing = dmarc in ("reject", "quarantine")

    slugs = [s for s in prof["slugs"] if rng.random() < 0.55]
    if is_m365 and "microsoft365" not in slugs:
        slugs.append("microsoft365")
    if not is_m365 and "google-workspace" not in slugs:
        slugs.append("google-workspace")
    if gateway:
        slugs.append("proofpoint" if group == "fintech" else "mimecast")

    posteriors = [
        _node(rng, "m365_tenant", is_m365, thin=thin and is_m365),
        _node(rng, "google_workspace_tenant", not is_m365, thin=thin and not is_m365),
        _node(rng, "email_gateway_present", gateway),
        _node(rng, "email_security_policy_enforcing", enforcing, declarative=True),
        _node(rng, "federated_identity", rng.random() < 0.4),
    ]
    return {
        "tenant_id": f"{brand[:8]}-0000-0000-0000-000000000000" if is_m365 else None,
        "display_name": brand.replace("-", " ").title(),
        "default_domain": domain,
        "queried_domain": domain,
        "provider": "Microsoft 365" if is_m365 else "Google Workspace",
        "confidence": "high" if not thin else "medium",
        "dmarc_policy": dmarc,
        "evidence": (
            [
                {
                    "source_type": "DMARC",
                    "raw_value": f"v=DMARC1; p={dmarc}",
                    "rule_name": "DMARC",
                    "slug": "dmarc",
                }
            ]
            if dmarc is not None
            else []
        ),
        "mta_sts_mode": mta,
        "email_gateway": ("Proofpoint" if group == "fintech" else "Mimecast") if gateway else None,
        "email_security_score": (4 if enforcing else 1) + (1 if mta else 0),
        "cloud_instance": cloud,
        "slugs": sorted(set(slugs)),
        "services": ["Microsoft 365"] if is_m365 else ["Google Workspace"],
        "sources": ["dns", "ct", "oidc"],
        "degraded_sources": [],
        "fusion_enabled": True,
        "record_type": "tenant",
        "schema_version": "2.0",
        "posterior_observations": posteriors,
    }


def main() -> int:
    rng = random.Random(20260606)
    groups = list(_PROFILES)
    here = os.path.dirname(os.path.abspath(__file__))
    records: list[dict[str, object]] = []
    grouping: list[tuple[str, str]] = []
    for i, brand in enumerate(_BRANDS):
        group = groups[i % len(groups)]
        rec = _record(rng, brand, group)
        records.append(rec)
        grouping.append((str(rec["queried_domain"]), group))

    with open(os.path.join(here, "synthetic_cohort.ndjson"), "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    with open(os.path.join(here, "synthetic_groups.csv"), "w", encoding="utf-8") as fh:
        fh.write("domain,label\n")
        for dom, grp in grouping:
            fh.write(f"{dom},{grp}\n")
    print(f"wrote {len(records)} synthetic records across {len(groups)} groups")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
