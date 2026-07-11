"""Tests for CT subdomain lexical taxonomy (recon_tool.lexical).

Covers:
- Environment prefix recognition (dev, staging, prod, uat, …)
- Region prefix recognition (us-east, eu-west, apne1, …)
- Tenancy shard pattern recognition (t-1234, org-abc, …)
- MIN_MATCHES threshold — a single match does NOT fire a signal
- Base-domain stripping
- Hedged language in emitted observations
- Wildcard subdomains are ignored
- Label boundary requirement — "europe" does not match "eu"
- Multi-category classification (dev-us-east-1 hits both env and region)
"""

from __future__ import annotations

import pytest

from recon_tool.lexical import (
    MIN_MATCHES,
    LexicalObservation,
    classify_subdomains,
    lexical_observations,
)

# ── Classification ──────────────────────────────────────────────────────


class TestEnvironmentClassification:
    def test_exact_match(self):
        out = classify_subdomains(["dev.contoso.com"], "contoso.com")
        assert "dev" in out["env"]

    def test_prefix_with_digit(self):
        out = classify_subdomains(["dev01.contoso.com"], "contoso.com")
        assert "dev01" in out["env"]

    def test_prefix_with_dash(self):
        out = classify_subdomains(["stg-web.contoso.com"], "contoso.com")
        assert "stg-web" in out["env"]

    def test_suffix_after_dash(self):
        out = classify_subdomains(["api-staging.contoso.com"], "contoso.com")
        assert "api-staging" in out["env"]

    def test_multiple_envs(self):
        out = classify_subdomains(
            ["dev.contoso.com", "stg.contoso.com", "prod.contoso.com"],
            "contoso.com",
        )
        assert len(out["env"]) == 3

    def test_preprod_is_env(self):
        out = classify_subdomains(["preprod.contoso.com"], "contoso.com")
        assert "preprod" in out["env"]

    def test_sbx_is_env(self):
        out = classify_subdomains(["sbx-api.contoso.com"], "contoso.com")
        assert "sbx-api" in out["env"]

    def test_does_not_match_unrelated_words(self):
        out = classify_subdomains(["developers.contoso.com"], "contoso.com")
        # "dev" is followed by "e" which is not a separator — no match
        assert out["env"] == []


class TestRegionClassification:
    def test_us_east(self):
        out = classify_subdomains(["us-east-1-api.contoso.com"], "contoso.com")
        assert any("us-east" in r for r in out["region"])

    def test_eu_west(self):
        out = classify_subdomains(["eu-west-1.contoso.com"], "contoso.com")
        assert any("eu-west" in r for r in out["region"])

    def test_apac(self):
        out = classify_subdomains(["ap-southeast-2.contoso.com"], "contoso.com")
        assert any("ap-southeast" in r for r in out["region"])

    def test_short_region_code(self):
        out = classify_subdomains(["apne1.contoso.com"], "contoso.com")
        assert any("apne1" in r for r in out["region"])

    def test_does_not_match_europe(self):
        """'europe' is not 'eu-west' — must not match a region."""
        out = classify_subdomains(["europe.contoso.com"], "contoso.com")
        assert out["region"] == []

    def test_region_after_substring_collision(self):
        # "house1-use1": the region code "use1" also appears inside "house1"
        # without a boundary. The matcher must scan past that first occurrence
        # to the valid trailing "-use1" rather than stop at the first hit.
        out = classify_subdomains(["house1-use1.contoso.com"], "contoso.com")
        assert any("use1" in r for r in out["region"])


class TestShardClassification:
    def test_t_dash_digits(self):
        out = classify_subdomains(["t-1234.contoso.com"], "contoso.com")
        assert len(out["shard"]) == 1

    def test_org_shard(self):
        out = classify_subdomains(["org-acme.contoso.com"], "contoso.com")
        assert len(out["shard"]) == 1

    def test_tenant_shard(self):
        out = classify_subdomains(["tenant-xyz.contoso.com"], "contoso.com")
        assert len(out["shard"]) == 1

    def test_short_t_rejected(self):
        """t-12 is too short — only 3+ digit shards count."""
        out = classify_subdomains(["t-12.contoso.com"], "contoso.com")
        assert out["shard"] == []


class TestMultiCategory:
    def test_dev_and_region(self):
        out = classify_subdomains(["dev-eu-west-1.contoso.com"], "contoso.com")
        # Matches environment (dev) AND region (eu-west)
        assert out["env"]
        assert out["region"]


class TestBaseDomainHandling:
    def test_strips_base_domain(self):
        out = classify_subdomains(["dev.sub.contoso.com"], "contoso.com")
        # The first label of "dev.sub" is "dev" — should match env
        assert "dev" in out["env"]

    def test_no_base_domain(self):
        out = classify_subdomains(["dev.contoso.com"])
        # Without base_domain, first label is still "dev"
        assert "dev" in out["env"]


class TestWildcardSkipping:
    def test_wildcard_ignored(self):
        out = classify_subdomains(["*.contoso.com", "dev.contoso.com"], "contoso.com")
        assert len(out["env"]) == 1


# ── Observations ────────────────────────────────────────────────────────


class TestObservationThreshold:
    def test_single_match_does_not_fire(self):
        """One matching subdomain is coincidence, not a pattern."""
        obs = lexical_observations(["dev.contoso.com"], "contoso.com")
        assert obs == []

    def test_meets_min_matches(self):
        obs = lexical_observations(
            ["dev.contoso.com", "stg.contoso.com"],
            "contoso.com",
        )
        assert len(obs) == 1
        assert obs[0].category == "Environment-like Labels"
        assert obs[0].match_count >= MIN_MATCHES

    def test_min_matches_is_two(self):
        assert MIN_MATCHES == 2


class TestObservationLanguage:
    def test_env_observation_reports_count_and_compatible_explanations(self):
        obs = lexical_observations(
            ["dev.contoso.com", "stg.contoso.com", "prod.contoso.com"],
            "contoso.com",
        )
        assert obs
        stmt = obs[0].statement.lower()
        assert stmt.startswith("3 observed public names")
        assert "compatible explanations" in stmt
        assert "mature environment" not in stmt
        assert "deployment pipeline" not in stmt

    def test_region_observation_is_hedged(self):
        obs = lexical_observations(
            ["us-east-1.contoso.com", "eu-west-1.contoso.com"],
            "contoso.com",
        )
        assert any(o.category == "Region-like Labels" for o in obs)
        geo = next(o for o in obs if o.category == "Region-like Labels")
        assert geo.statement.lower().startswith("2 observed public names")
        assert "geo-distributed infrastructure" not in geo.statement.lower()
        assert "multi-region deployment" not in geo.statement.lower()

    def test_shard_observation_is_hedged(self):
        obs = lexical_observations(
            ["t-1234.contoso.com", "org-acme.contoso.com"],
            "contoso.com",
        )
        tenant = next(o for o in obs if o.category == "Tenant-like Labels")
        assert tenant.statement.lower().startswith("2 observed public names")
        assert "multi-tenant sharding" not in tenant.statement.lower()
        assert "isolation architecture" not in tenant.statement.lower()

    def test_sample_labels_capped_at_3(self):
        subs = [
            "dev.contoso.com",
            "stg.contoso.com",
            "prod.contoso.com",
            "uat.contoso.com",
            "qa.contoso.com",
        ]
        obs = lexical_observations(subs, "contoso.com")
        assert obs[0].match_count == 5
        assert len(obs[0].sample_labels) == 3


class TestMultipleCategoriesObserved:
    def test_env_and_region_both_fire(self):
        subs = [
            "dev.contoso.com",
            "stg.contoso.com",
            "us-east-1.contoso.com",
            "eu-west-1.contoso.com",
        ]
        obs = lexical_observations(subs, "contoso.com")
        categories = {o.category for o in obs}
        assert "Environment-like Labels" in categories
        assert "Region-like Labels" in categories


# ── Data class ──────────────────────────────────────────────────────────


class TestLexicalObservationDataclass:
    def test_frozen(self):
        obs = LexicalObservation(
            category="X",
            statement="Y",
            match_count=2,
            sample_labels=("a", "b"),
        )
        with pytest.raises(AttributeError):
            obs.category = "Z"  # pyright: ignore[reportAttributeAccessIssue]
