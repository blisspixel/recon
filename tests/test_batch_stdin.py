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

from recon_tool import cli
from recon_tool.cli import _BatchInputError, _read_batch_domains, app  # pyright: ignore[reportPrivateUsage]
from recon_tool.models import ConfidenceLevel, SourceResult, TenantInfo

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
SAMPLE_RESULTS = [SourceResult(source_name="oidc_discovery", tenant_id=SAMPLE_INFO.tenant_id)]


def test_read_batch_domains_skips_blanks_and_comments() -> None:
    stream = io.StringIO("contoso.com\n# a comment\n\n  fabrikam.com  \n")
    assert _read_batch_domains(stream) == ["contoso.com", "fabrikam.com"]


def test_read_batch_domains_enforces_domain_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_MAX_BATCH_DOMAINS", 2)
    stream = io.StringIO("a.com\nb.com\nc.com\n")
    with pytest.raises(_BatchInputError, match="maximum of 2 domains"):
        _read_batch_domains(stream)


def test_read_batch_domains_enforces_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_MAX_BATCH_FILE_BYTES", 8)
    stream = io.StringIO("aaaa.com\nbbbb.com\n")
    with pytest.raises(_BatchInputError, match="maximum size"):
        _read_batch_domains(stream)


@patch(RESOLVE_PATH, new_callable=AsyncMock)
def test_batch_reads_domains_from_stdin(mock_resolve: AsyncMock) -> None:
    mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
    result = runner.invoke(app, ["batch", "-", "--json"], input="contoso.com\nfabrikam.com\n")
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) == 2


def test_batch_empty_stdin_is_validation_error() -> None:
    result = runner.invoke(app, ["batch", "-"], input="# only a comment\n\n")
    assert result.exit_code == cli.EXIT_VALIDATION
    assert "No domains found in stdin" in result.output
