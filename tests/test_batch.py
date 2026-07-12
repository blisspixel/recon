"""Tests for CLI batch mode."""

from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from recon_tool import bayesian
from recon_tool.cli import app
from recon_tool.cli.batch import _batch_apply_fusion
from recon_tool.models import (
    CandidateValue,
    ConfidenceLevel,
    MergeConflicts,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)

runner = CliRunner()

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Contoso Ltd",
    default_domain="contoso.onmicrosoft.com",
    queried_domain="contoso.com",
    confidence=ConfidenceLevel.HIGH,
    sources=("oidc_discovery",),
    services=("Microsoft 365",),
    slugs=("microsoft365",),
)

SAMPLE_RESULTS = [
    SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
]


class TestBatchCommand:
    """Tests for the batch subcommand."""

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_json_output(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\nexample.com\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["display_name"] == "Contoso Ltd"

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_markdown_output(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--md"])
        assert result.exit_code == 0
        assert "# " in result.output
        assert "Contoso Ltd" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_default_panel_output(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\n")

        result = runner.invoke(app, ["batch", str(domain_file)])
        assert result.exit_code == 0
        assert "Contoso Ltd" in result.output

    def test_batch_file_not_found(self):
        result = runner.invoke(app, ["batch", "nonexistent.txt"])
        assert result.exit_code == 2

    def test_batch_empty_file(self, tmp_path):
        domain_file = tmp_path / "empty.txt"
        domain_file.write_text("# just a comment\n\n")

        result = runner.invoke(app, ["batch", str(domain_file)])
        assert result.exit_code == 2

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_skips_comments_and_blanks(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("# header\ncontoso.com\n\n# another comment\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_json_handles_errors(self, mock_resolve, tmp_path):
        mock_resolve.side_effect = ReconLookupError(
            domain="bad.com",
            message="No data",
            error_type="all_sources_failed",
        )
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("bad.com\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert "error" in data[0]

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_json_handles_invalid_domain(self, mock_resolve, tmp_path):
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("not a domain\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert "error" in data[0]

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_concurrency_clamped(self, mock_resolve, tmp_path):
        """Concurrency is clamped to 1-20 range."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\n")

        # -c 0 should be clamped to 1, -c 100 to 20 — both should work
        result = runner.invoke(app, ["batch", str(domain_file), "--json", "-c", "0"])
        assert result.exit_code == 0
        result = runner.invoke(app, ["batch", str(domain_file), "--json", "-c", "100"])
        assert result.exit_code == 0

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_timeout_passed_to_resolver(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json", "--timeout", "7"])

        assert result.exit_code == 0
        assert mock_resolve.await_args.kwargs["timeout"] == 7.0

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_fusion_json_preserves_conflict_provenance(self, mock_resolve, tmp_path):
        conflicts = MergeConflicts(
            auth_type=(
                CandidateValue(value="Federated", source="graph", confidence="high"),
                CandidateValue(value="Managed", source="openid_config", confidence="medium"),
            ),
        )
        info = replace(SAMPLE_INFO, merge_conflicts=conflicts)
        mock_resolve.return_value = (info, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json", "--fusion"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        posterior = data[0]["posterior_observations"]
        assert posterior
        assert posterior[0]["conflict_provenance"] == [
            {"field": "auth_type", "sources": ["graph", "openid_config"], "magnitude": 1.5}
        ]

    def test_batch_fusion_uses_supplied_configuration(self):
        network = object()
        priors_override = {"m365_tenant": 0.4}
        inference = bayesian.InferenceResult(
            posteriors=(),
            entropy_reduction=0.0,
            evidence_count=0,
            conflict_count=0,
        )

        with patch("recon_tool.bayesian.infer_from_tenant_info", return_value=inference) as infer:
            result = _batch_apply_fusion(
                SAMPLE_INFO,
                network=network,
                priors_override=priors_override,
            )

        infer.assert_called_once_with(
            SAMPLE_INFO,
            network=network,
            priors_override=priors_override,
        )
        assert result.posterior_observations == ()

    @patch("recon_tool.cli.batch._batch_process_one", new_callable=AsyncMock)
    def test_batch_loads_fusion_configuration_once(self, process_one, tmp_path):
        """Every domain in one batch shares one immutable inference snapshot."""
        process_one.return_value = {"record_type": "lookup"}
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\nexample.com\nexample.net\n")
        network = bayesian.load_network()
        priors_override = {"m365_tenant": 0.4}

        with (
            patch("recon_tool.bayesian.load_network", return_value=network) as network_loader,
            patch("recon_tool.bayesian.load_priors_override", return_value=priors_override) as override_loader,
        ):
            result = runner.invoke(app, ["batch", str(domain_file), "--json", "--fusion"])

        assert result.exit_code == 0
        assert process_one.await_count == 3
        network_loader.assert_called_once_with()
        override_loader.assert_called_once_with()
        for call in process_one.await_args_list:
            assert call.kwargs["fusion_network"] is network
            assert call.kwargs["fusion_priors_override"] is priors_override

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_skips_fusion_loaders_when_disabled(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\nexample.com\n")

        with (
            patch("recon_tool.bayesian.load_network") as network_loader,
            patch("recon_tool.bayesian.load_priors_override") as override_loader,
        ):
            result = runner.invoke(app, ["batch", str(domain_file), "--json", "--no-fusion"])

        assert result.exit_code == 0
        network_loader.assert_not_called()
        override_loader.assert_not_called()

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_fusion_loader_failure_preserves_json_records(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\nexample.com\n")

        with patch("recon_tool.bayesian.load_network", side_effect=ValueError("invalid model configuration")):
            result = runner.invoke(app, ["batch", str(domain_file), "--json", "--fusion"])

        assert result.exit_code == 0
        assert mock_resolve.await_count == 2
        assert json.loads(result.output) == [
            {
                "domain": "contoso.com",
                "error": "invalid model configuration",
                "error_kind": "lookup",
                "record_type": "error",
            },
            {
                "domain": "example.com",
                "error": "invalid model configuration",
                "error_kind": "lookup",
                "record_type": "error",
            },
        ]

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_fusion_loader_failure_preserves_ndjson_records(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\nexample.com\n")

        with patch("recon_tool.bayesian.load_priors_override", side_effect=ValueError("invalid prior override")):
            result = runner.invoke(app, ["batch", str(domain_file), "--ndjson", "--fusion"])

        assert result.exit_code == 0
        assert mock_resolve.await_count == 2
        records = [json.loads(line) for line in result.output.splitlines()]
        assert [record["domain"] for record in records] == ["contoso.com", "example.com"]
        assert all(record["error"] == "invalid prior override" for record in records)
        assert all(record["error_kind"] == "lookup" for record in records)
        assert all(record["record_type"] == "error" for record in records)
