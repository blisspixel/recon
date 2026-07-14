"""Tests for custom profile templates."""

from __future__ import annotations

from pathlib import Path

import pytest

from recon_tool.models import Observation
from recon_tool.profiles import (
    Profile,
    apply_profile,
    list_profiles,
    load_profile,
    reload_profiles,
)


def _obs(category: str, salience: str, statement: str, source_name: str = "") -> Observation:
    return Observation(
        category=category,
        salience=salience,
        statement=statement,
        related_slugs=(),
        source_name=source_name,
    )


@pytest.fixture(autouse=True)
def _isolate_profiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Each test gets a clean RECON_CONFIG_DIR so custom profiles don't leak."""
    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    reload_profiles()
    yield
    reload_profiles()


# ── Built-in profile discovery ──────────────────────────────────────────


class TestBuiltinProfiles:
    def test_fintech_loads(self):
        p = load_profile("fintech")
        assert p is not None
        assert p.name == "fintech"
        assert p.description

    def test_healthcare_loads(self):
        p = load_profile("healthcare")
        assert p is not None
        assert p.name == "healthcare"

    def test_saas_b2b_loads(self):
        p = load_profile("saas-b2b")
        assert p is not None

    def test_high_value_target_loads(self):
        p = load_profile("high-value-target")
        assert p is not None

    def test_public_sector_loads(self):
        p = load_profile("public-sector")
        assert p is not None

    def test_list_profiles_returns_all_builtins(self):
        names = {p.name for p in list_profiles()}
        assert "fintech" in names
        assert "healthcare" in names
        assert "saas-b2b" in names
        assert "high-value-target" in names
        assert "public-sector" in names

    def test_unknown_profile_returns_none(self):
        assert load_profile("nonexistent-profile") is None

    def test_builtin_boost_and_exclude_keys_are_real_posture_rules(self):
        """Every built-in profile's signal_boost / exclude_signals key must name a
        real posture rule (data/posture.yaml). Profiles reweight posture
        observations by their originating rule name, so a key that matches no
        rule is inert config and must not ship. This guards against the historic
        drift where profiles referenced signal display names that apply_profile
        never sees.
        """
        from recon_tool.posture import load_posture_rules

        rule_names = {rule.name for rule in load_posture_rules()}
        assert rule_names, "expected built-in posture rules to load"

        offenders: list[str] = []
        for profile in list_profiles():
            for key, _ in profile.signal_boost:
                if key not in rule_names:
                    offenders.append(f"{profile.name}.signal_boost[{key!r}]")
            for key in profile.exclude_signals:
                if key not in rule_names:
                    offenders.append(f"{profile.name}.exclude_signals[{key!r}]")
        assert not offenders, "profile keys do not name a posture rule: " + ", ".join(offenders)


# ── Custom profile loading ──────────────────────────────────────────────


class TestCustomProfiles:
    def test_custom_profile_loads_from_config_dir(self, tmp_path: Path):
        (tmp_path / "profiles").mkdir(parents=True, exist_ok=True)
        (tmp_path / "profiles" / "custom.yaml").write_text("name: custom\ndescription: Test custom\n", encoding="utf-8")
        reload_profiles()
        p = load_profile("custom")
        assert p is not None
        assert p.description == "Test custom"

    def test_custom_profile_overrides_builtin(self, tmp_path: Path):
        """A custom profile named 'fintech' overrides the built-in."""
        (tmp_path / "profiles").mkdir(parents=True, exist_ok=True)
        (tmp_path / "profiles" / "fintech.yaml").write_text(
            "name: fintech\ndescription: User override\n", encoding="utf-8"
        )
        reload_profiles()
        p = load_profile("fintech")
        assert p is not None
        assert p.description == "User override"

    def test_invalid_yaml_skipped(self, tmp_path: Path):
        (tmp_path / "profiles").mkdir(parents=True, exist_ok=True)
        (tmp_path / "profiles" / "bad.yaml").write_text("name: bad\ncategory_boost: not-a-dict\n", encoding="utf-8")
        reload_profiles()
        p = load_profile("bad")
        # Profile loads but invalid field defaults to empty
        assert p is not None
        assert p.category_boost == ()

    def test_missing_name_skipped(self, tmp_path: Path):
        (tmp_path / "profiles").mkdir(parents=True, exist_ok=True)
        (tmp_path / "profiles" / "noname.yaml").write_text("description: no name here\n", encoding="utf-8")
        reload_profiles()
        # No profile loads
        names = {p.name for p in list_profiles()}
        assert "noname" not in names

    def test_negative_multiplier_clamped(self, tmp_path: Path):
        (tmp_path / "profiles").mkdir(parents=True, exist_ok=True)
        (tmp_path / "profiles" / "neg.yaml").write_text(
            "name: neg\ncategory_boost:\n  email: -2.0\n",
            encoding="utf-8",
        )
        reload_profiles()
        p = load_profile("neg")
        assert p is not None
        assert p.boost_for_category("email") == 0.0

    def test_multiplier_keys_are_stripped_and_non_finite_values_are_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "profiles").mkdir(parents=True, exist_ok=True)
        (tmp_path / "profiles" / "finite.yaml").write_text(
            """name: finite
category_boost:
  " cloud ": 2.0
  email: .nan
  identity: .inf
  security: true
""",
            encoding="utf-8",
        )

        reload_profiles()
        profile = load_profile("finite")

        assert profile is not None
        assert profile.category_boost == (("cloud", 2.0),)
        assert profile.boost_for_category("cloud") == 2.0
        assert profile.boost_for_category("email") == 1.0


# ── apply_profile ───────────────────────────────────────────────────────


class TestApplyProfile:
    def test_none_profile_returns_unchanged(self):
        obs = (_obs("email", "medium", "X"),)
        assert apply_profile(obs, None) == obs

    def test_empty_profile_is_noop_except_reorder(self):
        profile = Profile(name="noop")
        obs = (
            _obs("email", "low", "A"),
            _obs("identity", "high", "B"),
        )
        out = apply_profile(obs, profile)
        # Same observations, possibly reordered
        assert len(out) == 2
        assert {o.statement for o in out} == {"A", "B"}

    def test_category_boost_elevates_salience(self):
        profile = Profile(
            name="boost",
            category_boost=(("email", 3.0),),
        )
        obs = (_obs("email", "low", "X"),)
        out = apply_profile(obs, profile)
        # low (score=1) × 3.0 = 3.0 → high (>=2.5)
        assert out[0].salience == "high"

    def test_2x_boost_promotes_low_to_medium(self):
        profile = Profile(
            name="boost2",
            category_boost=(("email", 2.0),),
        )
        obs = (_obs("email", "low", "X"),)
        out = apply_profile(obs, profile)
        # low (score=1) × 2.0 = 2.0 → medium (>=1.5, <2.5)
        assert out[0].salience == "medium"

    def test_signal_boost_elevates_salience(self):
        profile = Profile(
            name="sig",
            signal_boost=(("strong_email_security", 3.0),),
        )
        obs = (_obs("other", "low", "boosted", source_name="strong_email_security"),)
        out = apply_profile(obs, profile)
        assert out[0].salience == "high"

    def test_signal_boost_keys_on_source_name_not_statement(self):
        """The boost matches the rule name, not the rendered statement."""
        profile = Profile(name="sig", signal_boost=(("strong_email_security", 3.0),))
        # Statement equals the key but source_name does not, so no boost.
        obs = (_obs("other", "low", "strong_email_security", source_name="other_rule"),)
        out = apply_profile(obs, profile)
        assert out[0].salience == "low"

    def test_exclude_signals_removes_by_source_name(self):
        profile = Profile(name="exc", exclude_signals=("consumer_saas_sprawl",))
        obs = (
            _obs("saas_footprint", "medium", "Consumer SaaS observed", source_name="consumer_saas_sprawl"),
            _obs("email", "medium", "Other", source_name="strong_email_security"),
        )
        out = apply_profile(obs, profile)
        assert {o.statement for o in out} == {"Other"}

    def test_focus_categories_filters(self):
        profile = Profile(
            name="focus",
            focus_categories=("email",),
        )
        obs = (
            _obs("email", "medium", "KEEP"),
            _obs("infrastructure", "medium", "DROP"),
        )
        out = apply_profile(obs, profile)
        assert {o.statement for o in out} == {"KEEP"}

    def test_focus_categories_keeps_uncategorized(self):
        profile = Profile(
            name="focus",
            focus_categories=("email",),
        )
        obs = (
            _obs("", "medium", "UNCAT"),
            _obs("email", "medium", "EMAIL"),
        )
        out = apply_profile(obs, profile)
        assert {o.statement for o in out} == {"UNCAT", "EMAIL"}

    def test_exclude_signals_removes(self):
        profile = Profile(
            name="exclude",
            exclude_signals=("Startup",),
        )
        obs = (
            _obs("other", "medium", "Startup Tool Mix"),
            _obs("other", "medium", "Other"),
        )
        out = apply_profile(obs, profile)
        assert {o.statement for o in out} == {"Other"}

    def test_ordering_by_boosted_score(self):
        profile = Profile(
            name="order",
            category_boost=(("email", 3.0),),
        )
        obs = (
            _obs("infrastructure", "high", "INFRA"),  # score 3
            _obs("email", "medium", "EMAIL"),  # score 2 * 3 = 6
        )
        out = apply_profile(obs, profile)
        # Email should come first due to higher boosted score
        assert out[0].statement == "EMAIL"
        assert out[1].statement == "INFRA"

    def test_deterministic(self):
        profile = Profile(
            name="det",
            category_boost=(("email", 2.0),),
        )
        obs = (
            _obs("email", "medium", "A"),
            _obs("email", "medium", "B"),
            _obs("email", "medium", "C"),
        )
        out1 = apply_profile(obs, profile)
        out2 = apply_profile(obs, profile)
        assert out1 == out2


# ── Profile.boost_for_* helpers ─────────────────────────────────────────


class TestBoostHelpers:
    def test_case_insensitive_category(self):
        p = Profile(name="t", category_boost=(("Email", 2.0),))
        assert p.boost_for_category("email") == 2.0
        assert p.boost_for_category("EMAIL") == 2.0

    def test_signal_exact_match_only(self):
        p = Profile(name="t", signal_boost=(("Exact Signal", 1.5),))
        assert p.boost_for_signal("Exact Signal") == 1.5
        assert p.boost_for_signal("exact signal") == 1.0  # not lowercased

    def test_default_multiplier_is_one(self):
        p = Profile(name="t")
        assert p.boost_for_category("anything") == 1.0
        assert p.boost_for_signal("anything") == 1.0
