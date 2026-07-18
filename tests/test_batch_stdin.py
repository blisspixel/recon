"""`recon batch -` reads the domain list from stdin.

Covers the shared bounded reader (`_read_batch_domains`) directly and the
end-to-end stdin path through the CLI.
"""

from __future__ import annotations

import io
import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from recon_tool import cli, cli_batch
from recon_tool.cli import app
from recon_tool.cli_batch import _BatchInputError
from recon_tool.cli_batch import read_batch_domains as _read_batch_domains
from recon_tool.models import ConfidenceLevel, SourceResult, TenantInfo

runner = CliRunner()

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Synthetic Alpha Ltd",
    default_domain="alpha.onmicrosoft.com",
    queried_domain="alpha.invalid",
    confidence=ConfidenceLevel.HIGH,
    sources=("oidc_discovery",),
    services=("Microsoft 365",),
    slugs=("microsoft365",),
)
SAMPLE_RESULTS = [SourceResult(source_name="oidc_discovery", tenant_id=SAMPLE_INFO.tenant_id)]


def test_read_batch_domains_skips_blanks_and_comments() -> None:
    stream = io.StringIO("alpha.invalid\n# a comment\n\n  beta.invalid  \n")
    assert _read_batch_domains(stream) == ["alpha.invalid", "beta.invalid"]


def test_read_batch_domains_enforces_domain_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_batch, "_MAX_BATCH_DOMAINS", 2)
    stream = io.StringIO("a.invalid\nb.invalid\nc.invalid\n")
    with pytest.raises(_BatchInputError, match="maximum of 2 domains"):
        _read_batch_domains(stream)


def test_read_batch_domains_enforces_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_batch, "_MAX_BATCH_FILE_BYTES", 8)
    stream = io.StringIO("aaaa.invalid\nbbbb.invalid\n")
    with pytest.raises(_BatchInputError, match="maximum size"):
        _read_batch_domains(stream)


def test_read_batch_domains_rejects_overlong_line(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_batch, "_MAX_BATCH_LINE_BYTES", 8)
    stream = io.StringIO("averylongdomain.example\n")
    with pytest.raises(_BatchInputError, match="line exceeds maximum length"):
        _read_batch_domains(stream)


def test_read_batch_domains_enforces_utf8_line_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_batch, "_MAX_BATCH_LINE_BYTES", 8)
    stream = io.StringIO("ééé.com\n")
    with pytest.raises(_BatchInputError, match="line exceeds maximum length"):
        _read_batch_domains(stream)


def test_read_batch_domains_enforces_utf8_file_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_batch, "_MAX_BATCH_FILE_BYTES", 16)
    stream = io.StringIO("éé.com\néé.com\n")
    with pytest.raises(_BatchInputError, match="maximum size"):
        _read_batch_domains(stream)


def test_read_batch_domains_rejects_surrogateescaped_input() -> None:
    with pytest.raises(_BatchInputError, match="not valid UTF-8"):
        _read_batch_domains(io.StringIO("\udcff.example\n"))


@patch(RESOLVE_PATH, new_callable=AsyncMock)
def test_batch_reads_domains_from_stdin(mock_resolve: AsyncMock) -> None:
    mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
    result = runner.invoke(app, ["batch", "-", "--json"], input="alpha.invalid\nbeta.invalid\n")
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) == 2


@patch(RESOLVE_PATH, new_callable=AsyncMock)
def test_batch_deduplicates_inputs_by_canonical_apex(mock_resolve: AsyncMock) -> None:
    mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
    result = runner.invoke(
        app,
        ["batch", "-", "--json"],
        input="alpha.invalid\nwww.alpha.invalid\nhttps://mail.alpha.invalid/path\n",
    )
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.output)) == 1
    assert mock_resolve.await_count == 1


def test_batch_empty_stdin_is_validation_error() -> None:
    result = runner.invoke(app, ["batch", "-"], input="# only a comment\n\n")
    assert result.exit_code == cli.EXIT_VALIDATION
    assert "No domains found in stdin" in result.output


def test_batch_stdin_overlong_line_is_validation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_batch, "_MAX_BATCH_LINE_BYTES", 8)
    result = runner.invoke(app, ["batch", "-"], input="averylongdomain.example\n")
    assert result.exit_code == cli.EXIT_VALIDATION
    assert "line exceeds maximum length" in result.output
