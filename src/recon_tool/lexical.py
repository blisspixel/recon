"""Pure-rule lexical classification of observed public subdomain names.

This module categorizes subdomains by recognised prefix / suffix
patterns. It is deliberately narrow: only environment-like, region-like, and
tenant-like patterns produce observations. Function prefixes (``api.``,
``login.``, ``cdn.``) are observed but never emitted as a signal on
their own because they are too common to warrant a lexical summary. No ML, no
bundled embeddings, and no generated candidates are used. The taxonomy is a
pure re-projection of
subdomains recon already observed via CT or DNS.

Every emitted observation reports an exact count and examples. It also names
compatible explanations without selecting one. The minimum match threshold
(``MIN_MATCHES``) suppresses one-off labels but does not validate what a label
means operationally.

Called from ``merger.py`` after ``merge_results`` assembles the
TenantInfo. Populates ``TenantInfo.lexical_observations`` (a tuple of
hedged observation strings). Zero additional network calls.

Design rationale — why not ML?
    The user's intended-use policy bans bundled ML models and paid
    embeddings; the evidence-first invariant bans generating candidate
    subdomains that weren't observed. A pure-rule parser operating on
    the set of names CT already returned satisfies both constraints
    trivially. Rules can be audited by hand and fail closed — an ML
    classifier of the same size would be a black box that users
    cannot reason about.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "ENV_PREFIXES",
    "MIN_MATCHES",
    "REGION_PREFIXES",
    "TENANCY_SHARD_PATTERNS",
    "LexicalObservation",
    "classify_subdomains",
    "lexical_observations",
]


# Minimum number of distinct subdomains that must match a category
# before that category is allowed to emit an observation. The threshold
# reduces one-off lexical noise. It does not establish that the labels map to
# environments, regions, tenants, or any particular operational design.
MIN_MATCHES = 2


# ── Taxonomy tables ─────────────────────────────────────────────────────

# Environment prefixes. A label is considered an environment match when
# it equals the prefix exactly ("dev.example.com"), starts with the
# prefix followed by a separator ("dev-01.example.com",
# "dev1.example.com"), or exactly follows a separator ("api-dev.example
# .com"). The separator characters are ``-``, ``_``, and digits.
ENV_PREFIXES: tuple[str, ...] = (
    "dev",
    "development",
    "stg",
    "stage",
    "staging",
    "uat",
    "qa",
    "test",
    "tst",
    "sbx",
    "sandbox",
    "prd",
    "prod",
    "preprod",
    "preview",
)

# Region / datacenter prefixes — AWS / Azure / GCP / internal style.
# Match anywhere in the label, with word boundaries provided by ``-`` or
# ``.``. These are intentionally conservative — matching on "eu" alone
# produces too many false positives (e.g. ``europe``, ``eur``).
REGION_PREFIXES: tuple[str, ...] = (
    "us-east",
    "us-west",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west",
    "eu-west-1",
    "eu-west-2",
    "eu-central",
    "eu-central-1",
    "eu-north",
    "eu-north-1",
    "eu-south",
    "ap-southeast",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast",
    "ap-northeast-1",
    "ap-south",
    "ap-south-1",
    "ca-central",
    "sa-east",
    "me-south",
    "af-south",
    "usw2",
    "usw1",
    "use1",
    "use2",
    "euw1",
    "euw2",
    "euc1",
    "apne1",
    "apne2",
    "apse1",
    "apse2",
)

# Tenancy shard patterns — per-tenant or per-customer subdomains.
# These are regexes, not prefixes; they tolerate a leading letter
# followed by digits or a namespaced identifier.
TENANCY_SHARD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^t-?\d{3,}", re.IGNORECASE),  # t-1234, t1234
    re.compile(r"^org-?[a-z0-9]{3,}", re.IGNORECASE),  # org-abc123, org-acme
    re.compile(r"^tenant-?[a-z0-9]{3,}", re.IGNORECASE),  # tenant-xyz
    re.compile(r"^cust(?:omer)?-?[a-z0-9]{3,}", re.IGNORECASE),  # cust-abc, customer-xyz
    re.compile(r"^c\d{4,}", re.IGNORECASE),  # c12345
)

# Separator characters for environment/region matching. Digits act
# as separators for patterns like ``dev01``.
_SEPARATORS = frozenset("-_.0123456789")


# ── Data model ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LexicalObservation:
    """One count-and-example observation derived from the lexical taxonomy."""

    category: str  # "Environment-like Labels", "Region-like Labels", "Tenant-like Labels"
    statement: str
    match_count: int
    sample_labels: tuple[str, ...]


@dataclass(frozen=True)
class _ObservationCopy:
    """Claim-safe rendering contract for one lexical category."""

    category: str
    label_shape: str
    compatible_explanations: str
    limitation: str


_OBSERVATION_COPY: dict[str, _ObservationCopy] = {
    "env": _ObservationCopy(
        category="Environment-like Labels",
        label_shape="environment-like",
        compatible_explanations="environment naming, test fixtures, vendor defaults, or unrelated label conventions",
        limitation="the labels alone do not establish operational design or maturity",
    ),
    "region": _ObservationCopy(
        category="Region-like Labels",
        label_shape="region-like",
        compatible_explanations="regional naming, service replicas, vendor conventions, or unrelated label conventions",
        limitation="the labels alone do not establish where infrastructure runs",
    ),
    "shard": _ObservationCopy(
        category="Tenant-like Labels",
        label_shape="tenant-like",
        compatible_explanations="customer naming, opaque identifiers, test data, or unrelated label conventions",
        limitation="the labels alone do not establish tenancy boundaries or data separation",
    ),
}


# ── Matching helpers ────────────────────────────────────────────────────


def _label_matches_env(label: str) -> str | None:
    """Return the matching environment keyword, or None."""
    lower = label.lower()
    for env in ENV_PREFIXES:
        # Exact match
        if lower == env:
            return env
        # Prefix followed by separator/digit
        if lower.startswith(env) and len(lower) > len(env) and lower[len(env)] in _SEPARATORS:
            return env
        # Prefix after a separator (e.g. "api-dev", "app-staging")
        # Check every occurrence, not just the first: a label like "x-devx-dev"
        # has a non-matching first "-dev" and a valid trailing one.
        for sep in ("-", "_"):
            token = f"{sep}{env}"
            start = lower.find(token)
            while start >= 0:
                end = start + len(token)
                if end == len(lower) or lower[end] in _SEPARATORS:
                    return env
                start = lower.find(token, start + 1)
    return None


def _label_matches_region(label: str) -> str | None:
    """Return the matching region keyword, or None."""
    lower = label.lower()
    for region in REGION_PREFIXES:
        # Require a character boundary (separator, start, or end) on both sides
        # so "europe" does not match inside "eu-west-1". Scan every occurrence,
        # not just the first: a label like "house1-use1" has a non-boundary
        # first "use1" (inside "house1") and a valid trailing one. This mirrors
        # the all-occurrences fix in _label_matches_env above.
        start = lower.find(region)
        while start >= 0:
            end = start + len(region)
            left_ok = start == 0 or lower[start - 1] in _SEPARATORS
            right_ok = end == len(lower) or lower[end] in _SEPARATORS
            if left_ok and right_ok:
                return region
            start = lower.find(region, start + 1)
    return None


def _label_matches_shard(label: str) -> str | None:
    """Return the matching shard pattern name, or None."""
    for pattern in TENANCY_SHARD_PATTERNS:
        if pattern.match(label):
            return pattern.pattern
    return None


def _first_label(subdomain: str, base_domain: str | None) -> str:
    """Return the first label of a subdomain relative to base_domain.

    ``api.contoso.com`` with base ``contoso.com`` → ``"api"``.
    ``dev-1.prod.contoso.com`` with base ``contoso.com`` → ``"dev-1"``.
    If base_domain is None or the subdomain doesn't end with it, return
    the first label of the raw subdomain.
    """
    if base_domain and subdomain.lower().endswith(f".{base_domain.lower()}"):
        stem = subdomain[: -(len(base_domain) + 1)]
    else:
        stem = subdomain
    return stem.split(".")[0] if stem else subdomain


# ── Public API ──────────────────────────────────────────────────────────


def classify_subdomains(
    subdomains: list[str] | tuple[str, ...],
    base_domain: str | None = None,
) -> dict[str, list[str]]:
    """Classify each subdomain into taxonomy categories.

    Returns a mapping of category → list of matching labels. A single
    subdomain may appear in multiple categories (e.g. ``dev-eu-west-1``
    matches both environment and region).

    Args:
        subdomains: Iterable of subdomain hostnames.
        base_domain: Optional apex domain for label stripping. When
            supplied, ``api.contoso.com`` with base ``contoso.com``
            contributes the first-label ``"api"`` instead of the full
            hostname.

    Returns:
        Dict with keys ``"env"``, ``"region"``, ``"shard"``. Values are
        lists of labels (subdomain first-labels when base_domain is
        given; full subdomains otherwise). Empty lists for categories
        with no matches.
    """
    by_cat: dict[str, list[str]] = {"env": [], "region": [], "shard": []}
    seen_by_cat: dict[str, set[str]] = {"env": set(), "region": set(), "shard": set()}

    for sub in subdomains:
        if not sub or "*" in sub:
            continue
        label = _first_label(sub, base_domain)
        if not label:
            continue
        env = _label_matches_env(label)
        region = _label_matches_region(label)
        shard = _label_matches_shard(label)
        if env and label not in seen_by_cat["env"]:
            seen_by_cat["env"].add(label)
            by_cat["env"].append(label)
        if region and label not in seen_by_cat["region"]:
            seen_by_cat["region"].add(label)
            by_cat["region"].append(label)
        if shard and label not in seen_by_cat["shard"]:
            seen_by_cat["shard"].add(label)
            by_cat["shard"].append(label)

    return by_cat


def lexical_observations(
    subdomains: list[str] | tuple[str, ...],
    base_domain: str | None = None,
) -> list[LexicalObservation]:
    """Produce count-and-example observations from classified subdomains.

    Returns an observation for each category with at least
    ``MIN_MATCHES`` distinct matching labels. Categories below the
    threshold are not reported. Crossing the threshold reports repeated
    lexical shape only, not operational meaning.

    The ``sample_labels`` field carries up to 3 labels cited as evidence in
    the ``--explain`` output.

    Args:
        subdomains: Subdomains discovered via CT / DNS enrichment.
        base_domain: Optional apex domain for label stripping.

    Returns:
        List of LexicalObservation instances (may be empty).
    """
    by_cat = classify_subdomains(subdomains, base_domain)

    observations: list[LexicalObservation] = []
    for key in ("env", "region", "shard"):
        matches = by_cat[key]
        if len(matches) < MIN_MATCHES:
            continue
        copy = _OBSERVATION_COPY[key]
        sample = tuple(matches[:3])
        observations.append(
            LexicalObservation(
                category=copy.category,
                statement=(
                    f"{len(matches)} observed public names have {copy.label_shape} first labels "
                    f"(examples: {', '.join(sample)}). Compatible explanations include "
                    f"{copy.compatible_explanations}; {copy.limitation}."
                ),
                match_count=len(matches),
                sample_labels=sample,
            )
        )

    return observations
