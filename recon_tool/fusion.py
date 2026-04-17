"""Bayesian fusion — per-slug confidence from weighted evidence.

Tagged **experimental** in v0.11. Provides a principled alternative to the
hardcoded thresholds in ``merger.compute_detection_scores``. Opt-in via the
``--fusion`` CLI flag; never auto-enabled, never overrides the existing
confidence fields.

## Model

For each slug, maintain a Beta(α, β) distribution over "this slug is
genuinely present on the target". Each evidence record for the slug updates
the posterior:

    α_new = α_prior + success_weight
    β_new = β_prior + (failure_weight)  # currently always 0 for present evidence

where the success weight is determined by the evidence source type. Sources
with stronger informational content (OIDC tenant ID, DKIM signing) contribute
more than weaker ones (TXT tokens, CT subdomain presence).

The posterior mean α / (α + β) lands in [0, 1] and summarises the
tool's belief about the slug. Multiple corroborating evidence records drive
the posterior up; no evidence leaves the slug at its prior (not zero —
"absence of evidence is not evidence of absence" holds).

## Why no numpy

The Beta math here is elementary arithmetic. Adding numpy as a dependency for
``α / (α + β)`` would double install size for no benefit. If the model grows
(mixture priors, hierarchical Bayes, MCMC) numpy can come in via an extra.

## Why no likelihood terms (yet)

A full Bayesian treatment would compute P(evidence | slug present) via each
fingerprint's precision/recall on a labelled corpus. We don't have that
corpus. The current implementation treats each observation as additive weight
on α — crude but honest, and strictly better than the three-bucket threshold
output it replaces at the UX layer.
"""

from __future__ import annotations

from collections import defaultdict

from recon_tool.models import EvidenceRecord

__all__ = [
    "SOURCE_PRIORS",
    "SOURCE_WEIGHTS",
    "compute_slug_posteriors",
]

# Per-source-type Beta priors. Higher α means the tool trusts this source more
# strongly from the outset — one observation from a high-prior source shifts
# the posterior more than one from a low-prior source.
#
# Source types come from EvidenceRecord.source_type which is a free string
# today. These are the ones actually emitted across the codebase.
#
# Rationale:
#   - OIDC / HTTP identity endpoints: authoritative responses from the
#     vendor. Very reliable for the attribution they carry.
#   - DKIM: the vendor cryptographically signs mail for this domain.
#     Almost impossible to fake accidentally.
#   - MX: the domain's mail is routed to this provider. Strong direct evidence.
#   - TXT: verification tokens are strong attribution but can linger on
#     dormant accounts, so slightly weaker than MX/DKIM.
#   - NS / CAA / SRV: structural indicators; usually diagnostic but
#     sometimes generic.
#   - A / CNAME: ambiguous without context — many services share hosts.
SOURCE_PRIORS: dict[str, tuple[float, float]] = {
    # (alpha, beta)
    "OIDC": (8.0, 1.0),
    "HTTP": (8.0, 1.0),
    "USERREALM": (7.0, 1.0),
    "DKIM": (6.0, 1.0),
    "MX": (6.0, 1.0),
    "TXT": (4.0, 2.0),
    "NS": (4.0, 2.0),
    "CAA": (4.0, 2.0),
    "SRV": (4.0, 2.0),
    "A": (2.0, 2.0),
    "CNAME": (2.0, 2.0),
    "DMARC_RUA": (3.0, 2.0),
    "SUBDOMAIN_TXT": (3.0, 2.0),
    "SPF": (3.0, 2.0),
}

# Additive weight added to α each time a slug is observed via this source type.
# Falls back to 1.0 for unknown source types so unknown sources don't silently
# drop evidence.
SOURCE_WEIGHTS: dict[str, float] = {
    "OIDC": 3.0,
    "HTTP": 3.0,
    "USERREALM": 2.5,
    "DKIM": 2.5,
    "MX": 2.0,
    "TXT": 1.5,
    "NS": 1.5,
    "CAA": 1.0,
    "SRV": 1.5,
    "A": 0.5,
    "CNAME": 1.0,
    "DMARC_RUA": 1.5,
    "SUBDOMAIN_TXT": 1.5,
    "SPF": 1.0,
}

# Default prior for slugs with evidence from an unknown source type. Neutral
# and slightly favouring presence — evidence exists, we just don't have a
# reliability prior for the source.
_DEFAULT_PRIOR: tuple[float, float] = (3.0, 2.0)
_DEFAULT_WEIGHT: float = 1.0


def compute_slug_posteriors(
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[tuple[str, float], ...]:
    """Return posterior means over slugs given the evidence chain.

    The output is ``((slug, posterior_mean), …)`` sorted by posterior
    descending, then slug ascending for stable ordering. Posterior means are
    in [0, 1]. Slugs that appear only in evidence with a falsy slug field are
    skipped.

    This operates purely on already-collected evidence — no network calls, no
    additional lookups. Safe to call from cached pipeline data.
    """
    # For each slug: start from the prior matching its strongest evidence
    # source. For every additional evidence record on the same slug, add that
    # source's success weight to α. β is fixed at the prior (no negative
    # evidence in the current model).
    slug_alphas: dict[str, float] = defaultdict(float)
    slug_betas: dict[str, float] = defaultdict(float)
    slug_primed: set[str] = set()

    # Group by slug for deterministic iteration
    by_slug: dict[str, list[EvidenceRecord]] = defaultdict(list)
    for ev in evidence:
        if not ev.slug:
            continue
        by_slug[ev.slug].append(ev)

    for slug, records in by_slug.items():
        # Pick the prior from the highest-α source type seen for this slug
        best_prior: tuple[float, float] = _DEFAULT_PRIOR
        for ev in records:
            prior = SOURCE_PRIORS.get(ev.source_type, _DEFAULT_PRIOR)
            if prior[0] > best_prior[0]:
                best_prior = prior
        if slug not in slug_primed:
            slug_alphas[slug] = best_prior[0]
            slug_betas[slug] = best_prior[1]
            slug_primed.add(slug)

        for ev in records:
            weight = SOURCE_WEIGHTS.get(ev.source_type, _DEFAULT_WEIGHT)
            slug_alphas[slug] += weight

    posteriors: list[tuple[str, float]] = []
    for slug in slug_alphas:
        a = slug_alphas[slug]
        b = slug_betas[slug]
        total = a + b
        # total is always positive (alpha prior > 0 for all our source types)
        mean = a / total if total > 0 else 0.0
        posteriors.append((slug, round(mean, 4)))

    posteriors.sort(key=lambda x: (-x[1], x[0]))
    return tuple(posteriors)
