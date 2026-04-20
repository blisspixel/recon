"""CT subdomain lexical taxonomy — pure-rule classification of
CT-discovered subdomains for hedged maturity observations.

This module categorizes subdomains by recognised prefix / suffix
patterns. It is deliberately narrow: only environment, region, and
tenancy-shard patterns produce signals. Function prefixes (``api.``,
``login.``, ``cdn.``) are observed but never emitted as a signal on
their own — they are too common to warrant a posture claim, and the
signal-to-noise would be poor. No ML, no bundled embeddings, no
generated candidates — the taxonomy is a pure re-projection of
subdomains recon already observed via CT or DNS.

Every emitted observation is hedged. The same evidence fits many
interpretations, so the classification output uses neutral language
("observed", "pattern consistent with") and never commits to a
confidence verdict. The minimum match threshold (``MIN_MATCHES``)
prevents single-subdomain coincidences from firing signals.

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
# before that category is allowed to emit an observation. Prevents a
# single ``dev.contoso.com`` from implying "mature environment
# separation". Tuned empirically: below 2 is coincidence, at 2 a
# pattern is plausible, at 3+ a pattern is solid. We use 2 as the
# floor and surface the count in the observation so users can see
# the signal density.
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
    """A single hedged observation derived from the lexical taxonomy."""

    category: str  # "Environment Separation", "Geo-Distribution", "Multi-Tenant Sharding"
    statement: str
    match_count: int
    sample_labels: tuple[str, ...]


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
        idx = lower.find(f"-{env}")
        if idx >= 0 and (idx + 1 + len(env) == len(lower) or lower[idx + 1 + len(env)] in _SEPARATORS):
            return env
        idx = lower.find(f"_{env}")
        if idx >= 0 and (idx + 1 + len(env) == len(lower) or lower[idx + 1 + len(env)] in _SEPARATORS):
            return env
    return None


def _label_matches_region(label: str) -> str | None:
    """Return the matching region keyword, or None."""
    lower = label.lower()
    for region in REGION_PREFIXES:
        if region in lower:
            # Require at least one character boundary (dot, dash) so
            # "europe" doesn't match "eu-west-1".
            idx = lower.find(region)
            left_ok = idx == 0 or lower[idx - 1] in _SEPARATORS
            end = idx + len(region)
            right_ok = end == len(lower) or lower[end] in _SEPARATORS
            if left_ok and right_ok:
                return region
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
    """Produce hedged observations from classified subdomains.

    Returns an observation for each category with at least
    ``MIN_MATCHES`` distinct matching labels. Categories below the
    threshold are not reported — a single ``dev.example.com`` is not
    a maturity signal, it is a coincidence.

    All observations use neutral hedged language. The
    ``sample_labels`` field carries up to 3 labels cited as evidence
    in the ``--explain`` output.

    Args:
        subdomains: Subdomains discovered via CT / DNS enrichment.
        base_domain: Optional apex domain for label stripping.

    Returns:
        List of LexicalObservation instances (may be empty).
    """
    by_cat = classify_subdomains(subdomains, base_domain)

    observations: list[LexicalObservation] = []

    env_matches = by_cat["env"]
    if len(env_matches) >= MIN_MATCHES:
        sample = tuple(env_matches[:3])
        observations.append(
            LexicalObservation(
                category="Environment Separation",
                statement=(
                    "Mature environment separation pattern observed "
                    f"({len(env_matches)} environment-prefixed subdomains "
                    "e.g. " + ", ".join(sample) + ") — consistent with "
                    "multi-environment deployment pipelines. Observation, "
                    "not a verdict."
                ),
                match_count=len(env_matches),
                sample_labels=sample,
            )
        )

    region_matches = by_cat["region"]
    if len(region_matches) >= MIN_MATCHES:
        sample = tuple(region_matches[:3])
        observations.append(
            LexicalObservation(
                category="Geo-Distribution",
                statement=(
                    "Geo-distributed infrastructure pattern observed "
                    f"({len(region_matches)} region-prefixed subdomains "
                    "e.g. " + ", ".join(sample) + ") — consistent with "
                    "multi-region deployment. Observation, not a verdict."
                ),
                match_count=len(region_matches),
                sample_labels=sample,
            )
        )

    shard_matches = by_cat["shard"]
    if len(shard_matches) >= MIN_MATCHES:
        sample = tuple(shard_matches[:3])
        observations.append(
            LexicalObservation(
                category="Multi-Tenant Sharding",
                statement=(
                    "Multi-tenant sharding pattern observed "
                    f"({len(shard_matches)} tenant-sharded subdomains "
                    "e.g. " + ", ".join(sample) + ") — consistent with "
                    "per-tenant isolation architectures. Observation, "
                    "not a verdict."
                ),
                match_count=len(shard_matches),
                sample_labels=sample,
            )
        )

    return observations
