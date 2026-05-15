"""v2.0-prep — schema disposition table is enforced by a test.

The roadmap's v2.0 schema-lock disposition table is policy. This
test makes the policy mechanically checkable: every field the
disposition table promotes to stable must be present in
`docs/recon-schema.json` with the documented shape.

The test exists before v2.0 tag so the v1.9.11 doc-polish pass
can verify schema coverage as it strips EXPERIMENTAL labels. A
failure here means either:

- The schema is missing a field the disposition table promoted
  (the schema author forgot to add it).
- The disposition table promotes a field the schema does not have
  (the table is aspirational and lacks a backing implementation).
- The shape pinned in the disposition table no longer matches the
  schema (someone changed the shape without updating the table).

Each failure mode is fatal at v2.0 ship time and has to be
resolved before tag.
"""

from __future__ import annotations

import json
from pathlib import Path

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "docs" / "recon-schema.json"


def _load_schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _all_field_names(schema: dict) -> set[str]:
    """Collect every property name from the top-level schema and
    from each ``$defs`` definition. The disposition table doesn't
    require fields to be top-level; ``wildcard_sibling_clusters`` is
    nested in ``CertSummary``, ``ecosystem_hyperedges`` is a batch-
    wrapper field, and so on. This collector treats "present somewhere
    in the schema" as the load-bearing check."""
    names: set[str] = set()
    names.update(schema.get("properties", {}).keys())
    for defn in schema.get("$defs", {}).values():
        names.update(defn.get("properties", {}).keys())
    return names


# Fields the v2.0 disposition table promotes to stable. Keyed by
# field name with a one-line rationale so future contributors who
# fail this test can see why the field is on the list.
_V2_PROMOTED_FIELDS: dict[str, str] = {
    "posterior_observations": "v1.9.0 Bayesian posteriors with credible intervals.",
    "slug_confidences": "v1.9.0 per-slug posterior summary.",
    "chain_motifs": "v1.7.0 CNAME chain motif library hits.",
    "wildcard_sibling_clusters": "v1.7.0 cert-issuance SAN sibling clusters (nested in CertSummary).",
    "deployment_bursts": "v1.7.0 temporal CT issuance bursts (nested in CertSummary).",
    "infrastructure_clusters": "v1.8.0 Louvain co-occurrence clusters.",
    "evidence_conflicts": "v1.7.0 cross-source evidence conflict array.",
}

# Fields that the disposition table promotes but the current schema
# only documents in description text, not as a typed property. v1.9.11
# is the milestone for closing each gap (either add a batch-wrapper
# schema definition, or downgrade the disposition table entry).
# Track here so v2.0 cannot tag with an unresolved gap.
_V2_KNOWN_SCHEMA_GAPS: dict[str, str] = {
    "ecosystem_hyperedges": (
        "v1.8.0 batch-wrapper field. Schema documents only per-domain TenantInfo; "
        "v1.9.11 either adds the batch wrapper definition or moves this entry off "
        "the disposition table. See `validation/v2.0-prep-baseline.md`."
    ),
}


# Pinned shape for ``posterior_observations``. The disposition table
# names these field names explicitly; the test enforces each one is
# present in the schema's PosteriorObservation definition.
_POSTERIOR_OBSERVATION_SHAPE: tuple[str, ...] = (
    "name",
    "description",
    "posterior",
    "interval_low",
    "interval_high",
    "evidence_used",
    "n_eff",
    "sparse",
)


class TestSchemaContainsAllPromotedFields:
    """The schema must contain every field the disposition table
    promotes. Fail with an explicit list so a v1.9.11 contributor
    can see exactly which fields are missing."""

    def test_every_promoted_field_appears_somewhere_in_schema(self):
        schema = _load_schema()
        present = _all_field_names(schema)
        missing = {name: rationale for name, rationale in _V2_PROMOTED_FIELDS.items() if name not in present}
        assert not missing, (
            "v2.0 disposition table promotes fields that are not in the schema. "
            "Either add them to `docs/recon-schema.json` or update the disposition "
            "table to remove the promotion claim. Missing:\n  "
            + "\n  ".join(f"{name}: {rat}" for name, rat in missing.items())
        )


class TestPosteriorObservationShapePinned:
    """The disposition table pins the field set of
    ``posterior_observations``. The test enforces the shape so a
    v1.9.11 contributor who reshapes the field notices before v2.0
    tags."""

    def test_posterior_observation_has_documented_fields(self):
        schema = _load_schema()
        # The PosteriorObservation definition lives under $defs in
        # the schema. We look for it by name; if the def has been
        # renamed in a future refactor, the test surfaces that as a
        # KeyError rather than silently passing.
        defs = schema.get("$defs", {})
        candidates = [
            name for name in defs if "PosteriorObservation" in name or "posterior_observation" in name.lower()
        ]
        if not candidates:
            # Fall back: search for a def whose properties include all the
            # pinned shape names. Robust against the def being renamed.
            for name, defn in defs.items():
                if all(field in defn.get("properties", {}) for field in _POSTERIOR_OBSERVATION_SHAPE):
                    candidates = [name]
                    break

        assert candidates, (
            "Could not locate the PosteriorObservation definition in the schema. "
            "Either the def was renamed or removed; resolve before v2.0 tag."
        )

        def_name = candidates[0]
        props = defs[def_name].get("properties", {})
        missing = [field for field in _POSTERIOR_OBSERVATION_SHAPE if field not in props]
        assert not missing, (
            f"PosteriorObservation definition (under `$defs/{def_name}`) is missing "
            f"fields the v2.0 disposition table pins: {missing}. "
            "Add them to the schema or update the disposition table."
        )


class TestDispositionTableTestableAsList:
    """Sanity that the promoted-fields list is non-empty and each
    entry has a rationale. A regression that emptied the list would
    silently disable this enforcement; this test catches that."""

    def test_promoted_fields_list_is_non_empty(self):
        total = len(_V2_PROMOTED_FIELDS) + len(_V2_KNOWN_SCHEMA_GAPS)
        assert total >= 8, (
            f"v2.0 disposition table tracks {total} fields. "
            f"Expected at least 8 (the v1.7 + v1.8 + v1.9 experimental field set). "
            f"If the list shrunk intentionally, document why in the v2.0 CHANGELOG."
        )

    def test_each_promoted_field_has_a_rationale(self):
        for field, rationale in _V2_PROMOTED_FIELDS.items():
            assert rationale, f"promoted field {field!r} missing rationale"
            assert len(rationale) >= 10, f"promoted field {field!r} rationale too short"

    def test_each_known_gap_has_a_rationale(self):
        for field, rationale in _V2_KNOWN_SCHEMA_GAPS.items():
            assert rationale, f"known schema gap {field!r} missing rationale"
            assert len(rationale) >= 20, (
                f"known schema gap {field!r} rationale too short — must explain why the gap exists "
                f"and which release closes it."
            )


class TestKnownGapsResolveBeforeV20:
    """The known-gaps list is a v1.9.11 worklist. v2.0 must NOT tag
    with any entry still on this list — either the gap is closed
    (entry moved to ``_V2_PROMOTED_FIELDS`` once the schema has the
    field) or the disposition decision changes (entry removed from
    both). This test fires when an entry is still on the gap list at
    v2.0 tag time."""

    def test_no_unresolved_gaps_at_v20(self):
        # Read the package version directly to avoid coupling to a
        # specific import path. The check is "if version >= 2.0,
        # gaps must be empty".
        import recon_tool

        version_tuple = tuple(int(p) for p in recon_tool.__version__.split(".")[:2] if p.isdigit())
        if version_tuple < (2, 0):
            # v1.9.x is allowed to have unresolved gaps; the list is
            # the v1.9.11 worklist.
            return

        assert not _V2_KNOWN_SCHEMA_GAPS, (
            f"v2.0 cannot tag with unresolved schema gaps. The disposition table promotes "
            f"fields that are not in the schema as typed properties. Either add them to "
            f"`docs/recon-schema.json` or remove from the disposition table.\n\n"
            + "\n".join(f"  {f}: {r}" for f, r in _V2_KNOWN_SCHEMA_GAPS.items())
        )
