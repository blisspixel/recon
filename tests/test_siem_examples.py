"""SIEM consumption-example regression tests.

Pins the `examples/siem/` worked examples against schema drift. The
v2.0 schema lock turns recon's `--json` shape into a public contract;
the SIEM examples are the load-bearing demonstrations that the
contract is actually consumable. Without these tests, a future schema
rename could pass the existing schema-drift gate but silently break
the SIEM mappings, the scenario the quality bar said the CI gate must
catch.

What we verify:

  1. The shared sample input (``examples/sample-output.json``) parses
     as JSON and carries every top-level field the SIEM READMEs claim
     to map. A renamed schema field that drops one of these will fail
     the test before the SIEM example silently breaks.
  2. Each SIEM's expected-event/document file parses as JSON. A bad
     paste or trailing-comma typo fails the test.
  3. Each SIEM's README mapping table references paths that actually
     exist in the sample input. The README serves as the contract;
     this test reads the table and validates the left-hand column.

Deliberately *not* verified:

  * Live Splunk / Elasticsearch ingestion. These tests do not spin up
    real SIEM servers. They are too heavy for CI, and the file-shape contract
    is what we want to protect, not the SIEM's own parser behaviour.
  * Semantic correctness of the use-case SPL / DSL. Those are
    operator-tunable and intentionally not pinned.

Compatibility notes:

  * All filesystem operations use ``pathlib.Path`` and explicit
    ``encoding="utf-8"`` so the test passes identically on Linux,
    macOS, and Windows runners.
  * No subprocess, no Python-version-specific features. Runs cleanly
    on every supported Python version (3.11 through 3.14).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLES = _REPO_ROOT / "examples"
_SAMPLE_INPUT = _EXAMPLES / "sample-output.json"
_SIEM_DIR = _EXAMPLES / "siem"


# ── Shared input ────────────────────────────────────────────────────


def _load_sample_input() -> dict[str, Any]:
    """Load the shared sample input, with a clear failure if missing.

    Failing here is the right failure mode for downstream tests: the
    SIEM examples reference this file by name, so its absence is a
    structural break, not a per-test issue.
    """
    if not _SAMPLE_INPUT.exists():
        pytest.fail(
            f"missing shared SIEM-example input: {_SAMPLE_INPUT}. "
            "The SIEM consumption examples assume this fictional "
            "Synthetic Gamma sample is at examples/sample-output.json."
        )
    return json.loads(_SAMPLE_INPUT.read_text(encoding="utf-8"))


class TestSharedInput:
    """The fictional sample input carries the fields the SIEM
    READMEs claim to map. Renaming a schema field that the SIEM
    examples reference must fail here."""

    def test_sample_input_parses(self):
        data = _load_sample_input()
        assert isinstance(data, dict), "sample-output.json must be a JSON object"

    @pytest.mark.parametrize(
        "field",
        [
            # Detection-pipeline fields that BOTH SIEM READMEs map.
            "queried_domain",
            "display_name",
            "provider",
            "confidence",
            "auth_type",
            "dmarc_policy",
            "domain_count",
            "tenant_id",
            "default_domain",
            "region",
            "services",
            "insights",
            "tenant_domains",
            "related_domains",
        ],
    )
    def test_sample_input_has_field(self, field):
        data = _load_sample_input()
        assert field in data, (
            f"sample-output.json is missing top-level field {field!r}. "
            "The SIEM examples reference this field; either restore "
            "it to the sample, or update the SIEM READMEs to no "
            "longer claim the mapping."
        )


# ── Splunk example ──────────────────────────────────────────────────


_SPLUNK_DIR = _SIEM_DIR / "splunk"


class TestSplunkSearchSafety:
    """The published Splunk saved-search examples must use literal
    set-membership (in() inside mvfilter()), not regex alternation,
    when comparing slugs against a baseline. A previous version used
    ``match(current_slugs, mvjoin(baseline_slugs, "|"))`` which
    interprets slug values as a regex alternation; a slug containing
    ``.*`` would silently suppress the public-indicator change alert.

    Pinned here so a future edit to the SPL can't regress."""

    def test_savedsearch_uses_literal_set_membership(self):
        path = _SPLUNK_DIR / "savedsearches.conf"
        text = path.read_text(encoding="utf-8")
        assert "NOT in(current_slugs, baseline_slugs)" in text, (
            "Splunk public-indicator saved search must use NOT in(current_slugs, "
            "baseline_slugs) for literal set-membership; the old "
            "mvjoin/match pattern is regex-unsafe and was the audit finding "
            "this test pins."
        )

    def test_savedsearch_does_not_use_unsafe_regex_join(self):
        path = _SPLUNK_DIR / "savedsearches.conf"
        # Strip comment lines (starting with #) before checking. The
        # security commentary in this file deliberately names the
        # previous unsafe pattern in a `# ...` comment to explain why
        # the new pattern exists. Only the executable SPL (the
        # `search = ...` lines and continuations) must be clean.
        non_comment_lines = [
            line for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")
        ]
        executable_spl = "\n".join(non_comment_lines)
        assert "mvjoin(baseline_slugs" not in executable_spl, (
            "Splunk SPL must not pass baseline_slugs through mvjoin() to "
            "regex match(). That pattern was the v1.9.3.8 audit finding "
            "(slugs interpreted as regex alternation). Use literal "
            "set-membership via in() inside mvfilter() instead."
        )

    def test_readme_uses_literal_set_membership(self):
        path = _SPLUNK_DIR / "README.md"
        text = path.read_text(encoding="utf-8")
        assert "NOT in(current_slugs, baseline_slugs)" in text, (
            "Splunk README must document the safe (in()-based) pattern; operators copy-paste from here."
        )

    def test_readme_does_not_publish_unsafe_pattern(self):
        path = _SPLUNK_DIR / "README.md"
        text = path.read_text(encoding="utf-8")
        # The README may still mention the unsafe pattern in a "what
        # NOT to do" call-out, but only adjacent to a "Why" block
        # that explains the safety issue. Cheap proxy: if the unsafe
        # pattern appears, the safety call-out must appear too.
        if "mvjoin(baseline_slugs" in text:
            assert "regex" in text.lower() or "literal" in text.lower(), (
                "Splunk README mentions the unsafe regex-join pattern but "
                "does not document why it's unsafe. Either remove the "
                "pattern or add a safety call-out."
            )


class TestSplunkExample:
    """The Splunk example's expected event parses, and every recon
    JSON path the Splunk README claims to map is reachable in the
    sample input."""

    def test_directory_exists(self):
        assert _SPLUNK_DIR.is_dir(), f"missing {_SPLUNK_DIR}"

    def test_readme_exists(self):
        assert (_SPLUNK_DIR / "README.md").is_file()

    def test_props_conf_exists(self):
        assert (_SPLUNK_DIR / "props.conf").is_file()

    def test_savedsearches_conf_exists(self):
        assert (_SPLUNK_DIR / "savedsearches.conf").is_file()

    def test_expected_event_parses(self):
        path = _SPLUNK_DIR / "expected-splunk-event.json"
        assert path.is_file(), f"missing {path}"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert data.get("_sourcetype") == "recon:lookup"

    def test_expected_event_uses_canonical_input(self):
        """The Splunk expected event must surface the same
        display label as the canonical sample input. Catches a
        silent drift where someone updates the sample but forgets
        the worked SIEM example.
        """
        sample = _load_sample_input()
        expected = json.loads(
            (_SPLUNK_DIR / "expected-splunk-event.json").read_text(encoding="utf-8"),
        )
        assert expected["display_name"] == sample["display_name"], (
            f"Splunk expected-event display_name "
            f"({expected['display_name']!r}) drifted from sample-output.json "
            f"({sample['display_name']!r}). Regenerate the SIEM example "
            "or update the sample, whichever is the intended source."
        )
        assert expected["services{}"] == sample["services"]
        assert expected["slugs{}"] == sample["slugs"]
        assert expected["insights{}"] == sample["insights"]

    def test_readme_mapping_table_references_real_fields(self):
        """Parse the Splunk README's "recon JSON path" column and
        confirm every path is reachable in the sample input."""
        readme = (_SPLUNK_DIR / "README.md").read_text(encoding="utf-8")
        sample = _load_sample_input()
        paths = _extract_mapped_paths(readme)
        assert paths, "no recon JSON paths found in Splunk README mapping table"
        for path in paths:
            assert _path_reachable(sample, path), (
                f"Splunk README maps recon path {path!r}, but it is not "
                "reachable in examples/sample-output.json. Either restore "
                "the field, or update the README mapping."
            )


# ── Elastic example ─────────────────────────────────────────────────


_ELASTIC_DIR = _SIEM_DIR / "elastic"


class TestElasticExample:
    """The Elastic example's expected document parses, and every
    recon JSON path the Elastic README claims to map is reachable in
    the sample input."""

    def test_directory_exists(self):
        assert _ELASTIC_DIR.is_dir(), f"missing {_ELASTIC_DIR}"

    def test_readme_exists(self):
        assert (_ELASTIC_DIR / "README.md").is_file()

    def test_ingest_pipeline_parses(self):
        path = _ELASTIC_DIR / "ingest-pipeline.json"
        assert path.is_file(), f"missing {path}"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert "processors" in data
        assert isinstance(data["processors"], list)
        assert data["processors"], "ingest pipeline must define at least one processor"

    def test_index_template_parses(self):
        path = _ELASTIC_DIR / "index-template.json"
        assert path.is_file(), f"missing {path}"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert "index_patterns" in data
        assert "template" in data

        conflict_properties = data["template"]["mappings"]["properties"]["recon"]["properties"][
            "evidence_conflicts"
        ]["properties"]
        assert set(conflict_properties) == {"field", "candidates"}
        assert set(conflict_properties["candidates"]["properties"]) == {
            "value",
            "source",
            "confidence",
        }

    def test_expected_document_parses(self):
        path = _ELASTIC_DIR / "expected-elastic-document.json"
        assert path.is_file(), f"missing {path}"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        source = data.get("_source", {})
        assert isinstance(source, dict)
        assert source.get("event", {}).get("dataset") == "recon.lookup", (
            "expected Elastic document must carry event.dataset='recon.lookup'"
        )

    def test_expected_document_uses_canonical_input(self):
        sample = _load_sample_input()
        expected = json.loads(
            (_ELASTIC_DIR / "expected-elastic-document.json").read_text(encoding="utf-8"),
        )
        source = expected["_source"]
        assert source["recon"]["display_name"] == sample["display_name"], (
            "Elastic expected-document recon.display_name drifted from "
            "sample-output.json display_name; regenerate or fix sample."
        )
        assert "organization" not in source, (
            "Public identity display_name must not be promoted to ECS "
            "organization.name; recon does not verify a legal organization."
        )
        assert source["host"]["domain"] == sample["queried_domain"], (
            "Elastic expected-document host.domain drifted from sample-output.json queried_domain"
        )
        assert source["recon"]["services"] == sample["services"]
        assert source["recon"]["slugs"] == sample["slugs"]
        assert source["recon"]["insights"] == sample["insights"]

    def test_ingest_pipeline_preserves_display_name_semantics(self):
        pipeline = json.loads(
            (_ELASTIC_DIR / "ingest-pipeline.json").read_text(encoding="utf-8"),
        )
        renames = {
            processor["rename"]["field"]: processor["rename"]["target_field"]
            for processor in pipeline["processors"]
            if "rename" in processor
        }
        assert renames["display_name"] == "recon.display_name"
        assert renames["evidence_conflicts"] == "recon.evidence_conflicts"

    def test_readme_mapping_table_references_real_fields(self):
        readme = (_ELASTIC_DIR / "README.md").read_text(encoding="utf-8")
        sample = _load_sample_input()
        paths = _extract_mapped_paths(readme)
        assert paths, "no recon JSON paths found in Elastic README mapping table"
        for path in paths:
            assert _path_reachable(sample, path), (
                f"Elastic README maps recon path {path!r}, but it is not "
                "reachable in examples/sample-output.json. Either restore "
                "the field, or update the README mapping."
            )


# Interpretation semantics


class TestInterpretationSemantics:
    """SIEM examples must not turn evidence confidence into severity."""

    def test_splunk_worked_example_does_not_derive_severity(self):
        expected = json.loads(
            (_SPLUNK_DIR / "expected-splunk-event.json").read_text(encoding="utf-8"),
        )
        assert expected["confidence"] == "high"
        assert "_severity_derived" not in expected
        assert "_severity_numeric_derived" not in expected

    def test_elastic_worked_example_does_not_derive_severity(self):
        expected = json.loads(
            (_ELASTIC_DIR / "expected-elastic-document.json").read_text(encoding="utf-8"),
        )
        source = expected["_source"]
        assert source["recon"]["confidence"] == "high"
        assert "severity" not in source["event"]

    def test_elastic_pipeline_does_not_derive_severity(self):
        pipeline = json.loads(
            (_ELASTIC_DIR / "ingest-pipeline.json").read_text(encoding="utf-8"),
        )
        set_fields = {
            processor["set"]["field"] for processor in pipeline["processors"] if "set" in processor
        }
        assert "event.severity" not in set_fields

    def test_splunk_config_does_not_reference_unknown_timestamp_flag(self):
        props = (_SPLUNK_DIR / "props.conf").read_text(encoding="utf-8")
        assert "--emit-timestamp" not in props


# ── Top-level index README ──────────────────────────────────────────


class TestSiemIndex:
    """The cross-SIEM index README exists and lists both shipped
    examples. Prevents drift where a new SIEM gets added without
    updating the index, or vice versa."""

    def test_index_readme_exists(self):
        assert (_SIEM_DIR / "README.md").is_file()

    def test_index_readme_lists_both_siems(self):
        text = (_SIEM_DIR / "README.md").read_text(encoding="utf-8")
        assert "splunk/" in text.lower() or "splunk" in text.lower()
        assert "elastic/" in text.lower() or "elastic" in text.lower()


# ── Helpers ─────────────────────────────────────────────────────────


# Markdown table rows in the SIEM READMEs look like:
#   | `queried_domain`                      | `host.domain`            | … |
# We extract the first backticked path from each table row. Paths can
# include the dotted ``foo.bar[].baz`` shape for array-element traversal;
# the reachability check below understands that shape.
_MAPPING_ROW_RE = re.compile(r"^\|\s*`([^`]+)`\s*\|", re.MULTILINE)

# Header that introduces the "always-present" mapping table in each
# SIEM README. Paths in this section MUST be reachable in the canonical
# sample input. They represent the unconditional contract recon's JSON
# emits on every successful lookup.
_ALWAYS_PRESENT_HEADER = "Detection-pipeline fields (always present)"

# Header that introduces fusion array-element mappings. The arrays are always
# present, but are empty when the operator uses ``--no-fusion``. Element paths
# are therefore not reachable in the canonical sample, so the strict check
# stays scoped to the preceding scalar and whole-array mappings.
_FUSION_ONLY_HEADER = "Fusion-layer fields"


def _extract_mapped_paths(readme_text: str) -> list[str]:
    """Pull the recon JSON paths from the SIEM README's
    "Detection-pipeline fields (always present)" mapping table only.

    Returns the de-duplicated list, preserving first-seen order so
    parametrize output is stable across runs.

    Scoped to the leading always-present section because the fusion section's
    element paths are not reachable when the always-present arrays are empty.
    """
    section = _isolate_section(
        readme_text,
        _ALWAYS_PRESENT_HEADER,
        _FUSION_ONLY_HEADER,
    )
    seen: dict[str, None] = {}
    for match in _MAPPING_ROW_RE.finditer(section):
        path = match.group(1).strip()
        if path and path not in seen:
            seen[path] = None
    # Filter out non-recon paths the column may also carry. SIEM-side
    # field references start with the SIEM's own namespace (``event.``,
    # ``recon.``, ``host.``, ``organization.``) and are not recon JSON
    # paths.
    return [p for p in seen if not p.startswith(("event.", "recon.", "host.", "organization."))]


def _isolate_section(text: str, start_header: str, end_header: str) -> str:
    """Return the substring between two Markdown headers.

    ``start_header`` matches a substring of the heading line; the
    returned text begins after that line. ``end_header`` similarly
    truncates the substring before the next section. Returns an empty
    string if ``start_header`` doesn't appear. Callers handle that
    via the "no paths found" assertion in the test.
    """
    start_idx = text.find(start_header)
    if start_idx == -1:
        return ""
    after_start = text[start_idx + len(start_header) :]
    end_idx = after_start.find(end_header)
    if end_idx == -1:
        return after_start
    return after_start[:end_idx]


def _path_reachable(data: Any, path: str) -> bool:
    """Walk ``path`` (dotted, supports ``foo[]`` for "any element of
    foo's list value") into ``data`` and return True iff the leaf exists.

    Examples (against a recon JSON object):
      * ``queried_domain``         → top-level key
      * ``cert_summary.cert_count`` → nested dict
      * ``posterior_observations[]`` → array (truthy if non-empty)
      * ``posterior_observations[].name`` → field on at least one element
      * ``evidence_conflicts{}.field`` → same as above; both ``[]`` and
        ``{}`` accepted as table-syntax variants for "any element"

    Returns False on missing keys, type mismatches, or empty arrays
    when an array-element path was requested.
    """
    cur: Any = data
    # Normalize {} to [] for the array-element marker.
    normalized = path.replace("{}", "[]")
    parts = normalized.split(".")
    for part in parts:
        if part.endswith("[]"):
            key = part[:-2]
            if not isinstance(cur, dict) or key not in cur:
                return False
            arr = cur[key]
            if not isinstance(arr, list) or not arr:
                return False
            # Continue into the first element. The README contract
            # is "reachable on at least one element", which we
            # approximate with the first element. Heterogeneous-shape
            # arrays are not a recon pattern.
            cur = arr[0]
        else:
            if not isinstance(cur, dict) or part not in cur:
                return False
            cur = cur[part]
    return True
