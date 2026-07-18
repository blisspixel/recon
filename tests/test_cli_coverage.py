"""Additional CLI tests to improve coverage on uncovered paths."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from recon_tool.cli import _debug_callback, app, version_callback
from recon_tool.models import (
    ConfidenceLevel,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)

runner = CliRunner()

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Synthetic Alpha Ltd",
    default_domain="alpha.onmicrosoft.com",
    queried_domain="alpha.invalid",
    confidence=ConfidenceLevel.HIGH,
    region="NA",
    sources=("oidc_discovery", "dns_records"),
    services=("Exchange Online", "Microsoft 365", "Slack"),
    slugs=("microsoft365", "slack"),
    auth_type="Federated",
    insights=("Federated identity indicators observed (likely Okta)",),
    related_domains=("alpha-internal.invalid",),
    domain_count=3,
    tenant_domains=("alpha.invalid", "alpha.onmicrosoft.com", "alpha-internal.invalid"),
)

SAMPLE_RESULTS = [
    SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", region="NA"),
    SourceResult(source_name="dns_records", detected_services=("Slack",), detected_slugs=("slack",)),
]


class TestVersionAndDebug:
    def test_version_false_does_nothing(self):
        """version_callback(False) should not raise."""
        version_callback(False)

    def test_debug_false_does_nothing(self):
        """_debug_callback(False) should not raise."""
        _debug_callback(False)

    def test_debug_true_enables_both_package_namespaces(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--debug must include both logger namespaces without duplicates."""
        import logging

        loggers = [logging.getLogger(name) for name in ("recon", "recon_tool")]
        root = logging.getLogger()
        snapshots = [(logger.level, list(logger.handlers), logger.propagate) for logger in loggers]
        host_handlers = [logging.NullHandler() for _logger in loggers]
        root_records: list[logging.LogRecord] = []

        class _RootCapture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                root_records.append(record)

        root_handler = _RootCapture()
        try:
            for logger, host_handler in zip(loggers, host_handlers, strict=True):
                logger.handlers.clear()
                logger.addHandler(host_handler)
                logger.setLevel(logging.NOTSET)
                logger.propagate = True
            root.addHandler(root_handler)

            _debug_callback(True)
            first_counts = [len(logger.handlers) for logger in loggers]
            _debug_callback(True)

            assert all(logger.level == logging.DEBUG for logger in loggers)
            assert all(not logger.propagate for logger in loggers)
            assert first_counts == [2, 2]
            assert [len(logger.handlers) for logger in loggers] == first_counts
            assert all(
                sum(handler.get_name() == "recon-cli-debug" for handler in logger.handlers) == 1
                for logger in loggers
            )
            assert all(
                host_handler in logger.handlers
                for logger, host_handler in zip(loggers, host_handlers, strict=True)
            )

            logging.getLogger("recon").debug("core diagnostic")
            logging.getLogger("recon_tool.bayesian").debug("package diagnostic")
            captured = capsys.readouterr().err
            assert captured.count("core diagnostic") == 1
            assert captured.count("package diagnostic") == 1
            assert root_records == []
        finally:
            root.removeHandler(root_handler)
            for logger, (level, handlers, propagate) in zip(loggers, snapshots, strict=True):
                logger.handlers[:] = handlers
                logger.setLevel(level)
                logger.propagate = propagate


class TestLookupFlags:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_services_flag(self, mock_resolve):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        default = runner.invoke(app, ["lookup", "alpha.invalid", "--no-cache"])
        compatibility = runner.invoke(app, ["lookup", "alpha.invalid", "--services", "--no-cache"])

        assert default.exit_code == 0
        assert compatibility.exit_code == 0
        assert compatibility.output == default.output
        assert mock_resolve.await_count == 2

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_domains_flag(self, mock_resolve):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "alpha.invalid", "--domains"])
        assert result.exit_code == 0

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_full_flag(self, mock_resolve):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "alpha.invalid", "--full", "--no-cache"])
        assert result.exit_code == 0
        assert "Synthetic Alpha Ltd" in result.output


class TestDoctorFailures:
    @patch("dns.resolver.resolve")
    @patch("httpx.AsyncClient")
    def test_doctor_with_dns_failure(self, mock_http_cls, mock_dns):
        import dns.resolver

        mock_dns.side_effect = dns.resolver.NoNameservers("no nameservers")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_http_cls.return_value = mock_client

        result = runner.invoke(app, ["doctor"])
        # A failed core check (DNS here) now sets a non-zero exit so a script
        # can gate on `recon doctor`; the FAIL row is still rendered.
        assert result.exit_code == 1
        assert "FAIL" in result.output


class TestBatchEdgeCases:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_deduplicates(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("alpha.invalid\nalpha.invalid\nALPHA.INVALID\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_unexpected_error(self, mock_resolve, tmp_path):
        mock_resolve.side_effect = RuntimeError("network exploded")
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("alpha.invalid\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "error" in data[0]

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_panel_error_display(self, mock_resolve, tmp_path):
        """Batch in default (panel) mode should show errors inline."""
        mock_resolve.side_effect = ReconLookupError(
            domain="bad.invalid",
            message="No data",
            error_type="all_sources_failed",
        )
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("bad.invalid\n")

        result = runner.invoke(app, ["batch", str(domain_file)])
        assert result.exit_code == 0

    def test_batch_too_many_domains(self, tmp_path):
        domain_file = tmp_path / "big.txt"
        lines = "\n".join(f"domain{i}.invalid" for i in range(10001))
        domain_file.write_text(lines)

        result = runner.invoke(app, ["batch", str(domain_file)])
        assert result.exit_code == 2
