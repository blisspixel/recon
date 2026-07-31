"""Regression tests for CLI output and exit-code contracts.

These pin defects found in a maintenance review: a validation exit code that was
reclassified to an internal error, and machine-readable output streams (ndjson,
markdown) contaminated by a human notice or an internal error sentinel.
"""

from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.models import ConfidenceLevel, EvidenceRecord, ReconLookupError, SourceResult, TenantInfo

runner = CliRunner()

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"

_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Synthetic Alpha Ltd",
    default_domain="alpha.onmicrosoft.com",
    queried_domain="alpha.invalid",
    confidence=ConfidenceLevel.HIGH,
    sources=("oidc_discovery",),
    services=("Microsoft 365",),
    slugs=("microsoft365",),
)
_RESULTS = [SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]


class TestLookupExitContract:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_unknown_profile_exits_2_not_4(self, mock_resolve) -> None:
        """An unknown --profile is a validation error (exit 2), not an internal
        crash (exit 4), and must not print a bare 'Exit' line. The profile check
        raises typer.Exit(2) from inside the lookup try block, which was being
        caught by the generic handler and reclassified."""
        mock_resolve.return_value = (_INFO, _RESULTS)
        result = runner.invoke(app, ["alpha.invalid", "--profile", "totally-bogus-xyz"])
        assert result.exit_code == 2
        assert "Exit\n" not in result.output

    @pytest.mark.parametrize("detail_flag", ["--full", "--verbose"])
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_json_stdout_stays_parseable_with_human_detail(
        self,
        mock_resolve,
        detail_flag: str,
    ) -> None:
        mock_resolve.return_value = (_INFO, _RESULTS)

        result = runner.invoke(
            app,
            ["alpha.invalid", detail_flag, "--json", "--no-cache"],
        )

        assert result.exit_code == 0
        assert json.loads(result.stdout)["queried_domain"] == "alpha.invalid"
        assert result.stdout.lstrip().startswith("{")
        assert "oidc_discovery" in result.stderr

    @pytest.mark.parametrize(
        ("output_flag", "stdout_prefix"),
        [("--md", "#"), ("--plain", "tenant_id:")],
    )
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_document_stdout_stays_clean_with_full_detail(
        self,
        mock_resolve,
        output_flag: str,
        stdout_prefix: str,
    ) -> None:
        mock_resolve.return_value = (_INFO, _RESULTS)

        result = runner.invoke(
            app,
            ["alpha.invalid", "--full", output_flag, "--no-cache"],
        )

        assert result.exit_code == 0
        assert result.stdout.lstrip().startswith(stdout_prefix)
        assert "oidc_discovery" in result.stderr

    @pytest.mark.parametrize(
        ("error_type", "expected_code", "message"),
        [
            ("timeout", 4, "Resolution timed out after 5s for alpha.invalid"),
            ("all_sources_failed", 4, "All public sources failed for alpha.invalid"),
            ("no_data", 3, "No indicators observed"),
        ],
    )
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_structured_resolver_failures_keep_distinct_exit_semantics(
        self,
        mock_resolve,
        error_type: str,
        expected_code: int,
        message: str,
    ) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="alpha.invalid",
            message=message,
            error_type=error_type,
        )

        result = runner.invoke(app, ["alpha.invalid", "--no-cache"])

        assert result.exit_code == expected_code
        if error_type == "no_data":
            assert "No information found for alpha.invalid" in result.stderr
            assert "Run recon doctor" not in result.stderr
        else:
            assert message in result.stderr
            assert "No information found" not in result.stderr
            assert "Run recon doctor to check online source connectivity, then retry." in result.stderr
            assert result.stdout == ""


class TestBatchMachineOutputClean:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_ndjson_stdout_is_all_json(self, mock_resolve, tmp_path) -> None:
        """A duplicate domain must not inject a human 'duplicate(s) removed'
        notice into the ndjson stream: every non-empty stdout line must parse as
        JSON."""
        mock_resolve.return_value = (_INFO, _RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("alpha.invalid\nALPHA.INVALID\n", encoding="utf-8")

        result = runner.invoke(app, ["batch", str(domain_file), "--ndjson"])
        assert result.exit_code == 0
        for line in result.output.splitlines():
            if line.strip():
                json.loads(line)  # raises if any emitted line is not valid JSON

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_markdown_error_does_not_leak_sentinel(self, mock_resolve, tmp_path) -> None:
        """A resolve failure in --md mode must not echo the internal NUL error
        sentinel into stdout."""
        mock_resolve.side_effect = ReconLookupError(
            domain="broken.example", message="no data", error_type="no_data"
        )
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("broken.example\n", encoding="utf-8")

        result = runner.invoke(app, ["batch", str(domain_file), "--md"])
        assert "\x00" not in result.output
        assert "ERR:" not in result.output


class TestBadInputIsCleanError:
    """Foreseeable user mistakes must produce a clean error and exit code, not
    the last-resort 'please report a bug' crash handler."""

    def test_non_utf8_batch_input_exits_2(self, tmp_path) -> None:
        bad = tmp_path / "domains.txt"
        bad.write_bytes("alpha.invalid\n".encode("utf-16"))
        result = runner.invoke(app, ["batch", str(bad)])
        assert result.exit_code == 2

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_discover_output_to_directory_exits_2(self, mock_resolve, tmp_path) -> None:
        mock_resolve.return_value = (_INFO, [])
        result = runner.invoke(app, ["discover", "alpha.invalid", "--output", str(tmp_path)])
        assert result.exit_code == 2

    def test_md_with_exposure_is_rejected(self) -> None:
        # --exposure renders its own output and does not honor --md, so the flag
        # is rejected rather than silently dropped.
        result = runner.invoke(app, ["alpha.invalid", "--exposure", "--md"])
        assert result.exit_code == 2


def test_markdown_batch_reports_invalid_domains_instead_of_dropping_them(tmp_path) -> None:
    """Every batch output mode must account for every input row.

    Markdown alone discarded validation errors, so a run over a list with
    malformed rows produced a report with no trace of them: empty stdout, empty
    stderr, exit 0. JSON, NDJSON, CSV, and the default panel all reported them.
    """
    listing = tmp_path / "domains.txt"
    listing.write_text("not_a_domain\nalso bad\n", encoding="utf-8")

    result = runner.invoke(app, ["batch", str(listing), "--md"])

    assert result.exit_code == 0
    assert "not_a_domain" in result.stderr
    assert "also bad" in result.stderr


@patch(RESOLVE_PATH, new_callable=AsyncMock)
def test_plain_output_carries_requested_explain_and_posture_sections(mock_resolve: AsyncMock) -> None:
    """`--plain` is the screen-reader path, so it must not be the weakest one.

    It took neither flag, so `--plain --explain` and `--plain --posture` exited
    0 with the requested content silently dropped while `--json` and `--md`
    both honored them.
    """
    evidenced = replace(
        _INFO,
        evidence=(EvidenceRecord("HTTP", "NameSpaceType=Managed", "GetUserRealm", "microsoft365"),),
    )
    mock_resolve.return_value = (evidenced, _RESULTS)

    plain = runner.invoke(app, ["alpha.invalid", "--plain"])
    explained = runner.invoke(app, ["alpha.invalid", "--plain", "--explain"])
    # A profile is what produces posture observations; without one the block is
    # legitimately empty and an empty collection renders as no lines at all.
    posture = runner.invoke(app, ["alpha.invalid", "--plain", "--posture", "--profile", "fintech"])

    assert plain.exit_code == 0
    assert explained.exit_code == 0
    assert posture.exit_code == 0
    assert "explanation_dag" not in plain.stdout
    assert "posture" not in plain.stdout
    # The provenance DAG is the part of the --explain block that is always
    # populated; the flat `explanations` list can legitimately be empty, and an
    # empty collection renders as no lines at all in the linear view.
    assert "explanation_dag" in explained.stdout
    assert "relation: detected-by" in explained.stdout
    assert "posture" in posture.stdout
