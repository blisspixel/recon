"""Custom profile templates — reweight and filter posture observations
for a specific audience lens (v0.9.3).

A profile is a YAML file in either the built-in ``data/profiles/``
directory or in ``~/.recon/profiles/`` (override via
``RECON_CONFIG_DIR``). Profiles do NOT add new intelligence — they
reweight, reorder, and filter the observations and signals that the
existing pipeline already produces. The point is composition, not
extension: a CISO of a fintech organisation wants different framing
than a CISO of a healthcare provider, even though both are looking
at the same underlying evidence.

Schema
    A profile YAML file has this shape::

        name: fintech
        description: Fintech and payments oriented lens
        category_boost:
          email: 1.5       # multiplier applied to observations whose
                           # category matches this key
          identity: 1.3
          infrastructure: 0.8
        signal_boost:
          "DMARC Governance Investment": 2.0
          "Enterprise Security Stack": 1.5
        focus_categories:
          - email        # only observations in these categories are
                         # retained (empty/missing = all categories)
        exclude_signals:
          - "Startup Tool Mix"
        prepend_note: |
          This report uses the fintech profile — email and identity
          signals are weighted higher than infrastructure.

    Every field is optional except ``name``. A profile with only a
    ``name`` is valid and acts as a no-op.

Invariants
    * Profiles are ADDITIVE ONLY — they cannot introduce new
      observations, only reweight existing ones.
    * A profile with ``focus_categories`` filters observations to
      those categories, but any observation from an uncategorized
      source (e.g. consistency checks without a category tag) is
      retained. Filtering errs on the side of showing more, not less.
    * ``category_boost`` and ``signal_boost`` multiply the salience
      score of matching observations; the result is still capped at
      the ``high`` salience level — profiles cannot create false
      confidence out of thin air.
    * Applying a profile is deterministic: two runs with the same
      profile on the same data produce identical output.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from recon_tool.models import Observation

logger = logging.getLogger("recon")

__all__ = [
    "Profile",
    "apply_profile",
    "compute_baseline_anomalies",
    "list_profiles",
    "load_profile",
    "reload_profiles",
]


# ── Data model ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Profile:
    """A validated, immutable profile definition."""

    name: str
    description: str = ""
    category_boost: tuple[tuple[str, float], ...] = ()  # (category, multiplier)
    signal_boost: tuple[tuple[str, float], ...] = ()  # (signal_name, multiplier)
    focus_categories: tuple[str, ...] = ()
    exclude_signals: tuple[str, ...] = ()
    prepend_note: str = ""
    # v1.8 vertical-baseline anomaly rules. Each expected_categories
    # entry is a fingerprint *category* (e.g. ``Security``) that the
    # vertical typically uses; absence of any matching detected slug
    # surfaces a hedged "absence is observable" observation. Each
    # expected_motifs entry is a chain-motif name (from
    # data/motifs.yaml); absence on every related subdomain surfaces
    # the same kind of observation. Both are descriptive — they never
    # imply a verdict.
    expected_categories: tuple[str, ...] = ()
    expected_motifs: tuple[str, ...] = ()

    def boost_for_category(self, category: str) -> float:
        """Return the multiplier for this category, defaulting to 1.0."""
        for cat, mult in self.category_boost:
            if cat.lower() == category.lower():
                return mult
        return 1.0

    def boost_for_signal(self, name: str) -> float:
        """Return the multiplier for this signal name, defaulting to 1.0."""
        for sig, mult in self.signal_boost:
            if sig == name:
                return mult
        return 1.0


# ── Validation helpers ─────────────────────────────────────────────────


def _parse_mapping(raw: Any, profile_name: str, field_name: str) -> tuple[tuple[str, float], ...]:
    """Parse a dict-shaped field into a tuple of (key, multiplier) pairs.

    Rejects non-numeric values, negative values, and non-string keys
    with a warning. Returns an empty tuple when the field is missing
    or entirely invalid — never raises.
    """
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        logger.warning(
            "Profile %r has non-dict %s — ignored",
            profile_name,
            field_name,
        )
        return ()
    pairs: list[tuple[str, float]] = []
    for key, value in raw.items():  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(key, str) or not key.strip():
            logger.warning(
                "Profile %r has invalid %s key %r — skipped",
                profile_name,
                field_name,
                key,
            )
            continue
        try:
            mult = float(value)  # pyright: ignore[reportUnknownArgumentType]
        except (TypeError, ValueError):
            logger.warning(
                "Profile %r has non-numeric %s value %r for key %r — skipped",
                profile_name,
                field_name,
                value,
                key,
            )
            continue
        if mult < 0:
            logger.warning(
                "Profile %r has negative %s value %f for key %r — clamped to 0",
                profile_name,
                field_name,
                mult,
                key,
            )
            mult = 0.0
        pairs.append((key, mult))
    return tuple(pairs)


def _parse_string_list(raw: Any, profile_name: str, field_name: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        logger.warning(
            "Profile %r has non-list %s — ignored",
            profile_name,
            field_name,
        )
        return ()
    out: list[str] = []
    for entry in raw:  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(entry, str) or not entry.strip():
            logger.warning(
                "Profile %r has invalid %s entry %r — skipped",
                profile_name,
                field_name,
                entry,
            )
            continue
        out.append(entry.strip())
    return tuple(out)


def _build_profile(data: dict[str, Any], source: str) -> Profile | None:
    """Validate a raw YAML dict into a Profile. Returns None on failure."""
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        logger.warning("Profile in %s missing 'name' — skipped", source)
        return None
    name = name.strip()

    description_raw = data.get("description", "")
    description: str = description_raw if isinstance(description_raw, str) else ""

    prepend_raw = data.get("prepend_note", "")
    prepend: str = prepend_raw if isinstance(prepend_raw, str) else ""

    return Profile(
        name=name,
        description=description,
        category_boost=_parse_mapping(data.get("category_boost"), name, "category_boost"),
        signal_boost=_parse_mapping(data.get("signal_boost"), name, "signal_boost"),
        focus_categories=_parse_string_list(data.get("focus_categories"), name, "focus_categories"),
        exclude_signals=_parse_string_list(data.get("exclude_signals"), name, "exclude_signals"),
        prepend_note=prepend,
        expected_categories=_parse_string_list(data.get("expected_categories"), name, "expected_categories"),
        expected_motifs=_parse_string_list(data.get("expected_motifs"), name, "expected_motifs"),
    )


# ── Loader ──────────────────────────────────────────────────────────────


def _profile_search_dirs() -> list[Path]:
    """Return the ordered list of directories to search for profiles.

    Built-in first, custom second. A custom profile with the same
    name as a built-in OVERRIDES the built-in (this is the one
    exception to the usual additive-only invariant — profiles are
    user-facing lenses and explicit override is the expected mode).
    """
    builtin = Path(__file__).parent / "data" / "profiles"
    custom_dir = os.environ.get("RECON_CONFIG_DIR")
    custom = Path(custom_dir) / "profiles" if custom_dir else Path.home() / ".recon" / "profiles"
    return [builtin, custom]


@cache
def _load_all_profiles() -> dict[str, Profile]:
    """Load every profile YAML file from the search paths.

    Later paths (custom) override earlier paths (built-in) when the
    profile name matches. Returns a dict keyed by profile name.
    Results are cached for the process lifetime; call
    ``reload_profiles`` to clear.
    """
    profiles: dict[str, Profile] = {}
    for directory in _profile_search_dirs():
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.yaml")):
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError) as exc:
                logger.warning("Failed to load profile from %s: %s", path, exc)
                continue
            if not isinstance(raw, dict):
                logger.warning("Profile file %s is not a YAML mapping — skipped", path)
                continue
            profile = _build_profile(raw, str(path))
            if profile is None:
                continue
            profiles[profile.name] = profile
    return profiles


def load_profile(name: str) -> Profile | None:
    """Load a profile by name. Returns None if the profile doesn't exist."""
    return _load_all_profiles().get(name)


def list_profiles() -> tuple[Profile, ...]:
    """Return every loaded profile, sorted by name."""
    return tuple(sorted(_load_all_profiles().values(), key=lambda p: p.name))


def reload_profiles() -> None:
    """Clear the profile cache so the next call re-reads from disk."""
    _load_all_profiles.cache_clear()


# ── Application ─────────────────────────────────────────────────────────


_SALIENCE_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


def _score(obs: Observation) -> float:
    """Base numeric score for an observation (low=1, medium=2, high=3)."""
    return float(_SALIENCE_ORDER.get(obs.salience, 1) + 1)


def _salience_for_score(score: float) -> str:
    """Map a boosted score back to a salience level, capped at 'high'.

    Thresholds:
        score >= 2.5  → high
        score >= 1.5  → medium
        else          → low
    """
    if score >= 2.5:
        return "high"
    if score >= 1.5:
        return "medium"
    return "low"


def compute_baseline_anomalies(
    profile: Profile | None,
    detected_slugs: tuple[str, ...],
    chain_motif_names: tuple[str, ...],
) -> tuple[Observation, ...]:
    """Surface vertical-baseline anomalies as hedged observations (v1.8+).

    Compares the profile's ``expected_categories`` against the
    fingerprint categories implied by ``detected_slugs``, and the
    profile's ``expected_motifs`` against ``chain_motif_names``. Each
    expected item with no observed match becomes one Observation.

    Output is never a verdict — language is "absence is observable",
    salience is at most ``medium``, and category is ``consistency`` so
    the existing posture lens treats it like a hygiene check rather
    than a security finding. Returns an empty tuple when ``profile``
    is None or when no expected item is missing.
    """
    if profile is None:
        return ()
    if not profile.expected_categories and not profile.expected_motifs:
        return ()

    # Build a slug → category lookup once. Pulled lazily here to keep
    # the import out of the module top — profiles is loaded by
    # broader tooling that may not need fingerprints.
    from recon_tool.fingerprints import load_fingerprints

    slug_to_category: dict[str, str] = {fp.slug: fp.category for fp in load_fingerprints()}
    detected_categories = {
        slug_to_category[slug].lower() for slug in detected_slugs if slug in slug_to_category
    }
    detected_motifs = {name.lower() for name in chain_motif_names}

    out: list[Observation] = []
    for expected_cat in profile.expected_categories:
        if expected_cat.lower() in detected_categories:
            continue
        out.append(
            Observation(
                category="consistency",
                salience="medium",
                statement=(
                    f"{profile.name} profile expects fingerprint category "
                    f"'{expected_cat}'; not observed for this apex (absence "
                    f"is observable, not a verdict)."
                ),
                related_slugs=(),
            )
        )
    for expected_motif in profile.expected_motifs:
        if expected_motif.lower() in detected_motifs:
            continue
        out.append(
            Observation(
                category="consistency",
                salience="medium",
                statement=(
                    f"{profile.name} profile expects chain motif "
                    f"'{expected_motif}'; not observed on any related "
                    f"subdomain (absence is observable, not a verdict)."
                ),
                related_slugs=(),
            )
        )
    return tuple(out)


def apply_profile(
    observations: tuple[Observation, ...],
    profile: Profile | None,
) -> tuple[Observation, ...]:
    """Apply a profile to a tuple of posture observations.

    Steps, in order:
        1. If profile is None, return observations unchanged.
        2. Exclude observations whose statement matches any
           ``exclude_signals`` entry (exact substring match).
        3. When ``focus_categories`` is non-empty, filter to
           observations whose category is in that list (uncategorized
           observations are retained — filtering errs toward visibility).
        4. Multiply each observation's base score by the product of
           its category_boost and signal_boost multipliers. Re-map
           the boosted score to a salience level.
        5. Re-sort by boosted score (descending), then by original
           index for stability.

    The returned tuple preserves observation identity via dataclass
    replacement — only the salience field changes.
    """
    if profile is None:
        return observations

    from dataclasses import replace

    # Step 2: exclusion by statement substring
    filtered: list[Observation] = []
    for obs in observations:
        if any(excl in obs.statement for excl in profile.exclude_signals):
            continue
        filtered.append(obs)

    # Step 3: focus category filter
    if profile.focus_categories:
        focus_set = {c.lower() for c in profile.focus_categories}
        kept: list[Observation] = []
        for obs in filtered:
            if not obs.category or obs.category.lower() in focus_set:
                kept.append(obs)
        filtered = kept

    # Step 4: apply multipliers and rebuild salience
    boosted: list[tuple[float, int, Observation]] = []
    for idx, obs in enumerate(filtered):
        base = _score(obs)
        cat_mult = profile.boost_for_category(obs.category)
        sig_mult = profile.boost_for_signal(obs.statement)
        score = base * cat_mult * sig_mult
        new_salience = _salience_for_score(score)
        reweighted = replace(obs, salience=new_salience) if new_salience != obs.salience else obs
        boosted.append((score, idx, reweighted))

    # Step 5: sort by boosted score descending, then original index
    boosted.sort(key=lambda t: (-t[0], t[1]))
    return tuple(o for _, _, o in boosted)
