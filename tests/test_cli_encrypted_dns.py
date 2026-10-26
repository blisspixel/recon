"""The CLI's opt-in encrypted DNS view (RECON_DNS_VIEW=caller-safe).

The trusted CLI keeps host resolution unless the operator sets the exact
opt-in value. With it, collection binds the same immutable caller-safe policy
as MCP; an unusable view refuses before any collector runs and never falls
back to host DNS.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from recon_tool import network_policy, resolver
from recon_tool.cli import app
from recon_tool.cli.shared import cli_collection_context
from recon_tool.models import ReconLookupError
from recon_tool.network_policy import CollectionPolicy, cli_collection_policy, collection_scope, current_policy

runner = CliRunner()
RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"
GUIDE = "https://github.com/blisspixel/recon/blob/main/docs/getting-started.md#encrypted-dns"
INVALID = {"RECON_DNS_VIEW": "caller-safe", "RECON_DNS_TLS_NAME": "resolver.example.org"}


@pytest.mark.parametrize(
    "environment",
    [{}, {"RECON_DNS_VIEW": "operator"}, {"RECON_DNS_VIEW": "none"}, {"RECON_DNS_VIEW": "Caller-Safe"}],
)
def test_cli_keeps_host_dns_without_the_exact_opt_in(environment: dict[str, str]) -> None:
    assert cli_collection_policy(environment) is None


def test_cli_opt_in_binds_the_encrypted_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_policy, "_HOST_SERVERS", ("192.0.2.53",))
    policy = cli_collection_policy({"RECON_DNS_VIEW": "caller-safe"})
    assert policy is not None
    assert policy.available
    assert policy.servers == network_policy.DEFAULT_CALLER_SAFE_SERVERS
    assert policy.tls_name == network_policy.DEFAULT_CALLER_SAFE_TLS_NAME


def test_cli_opt_in_honors_saved_settings_and_refuses_invalid_ones() -> None:
    saved = cli_collection_policy(
        {"RECON_DNS_VIEW": "caller-safe", "RECON_DNS_SERVERS": "8.8.8.8", "RECON_DNS_TLS_NAME": "dns.google"}
    )
    assert saved is not None
    assert saved.servers == ("8.8.8.8",)
    assert saved.tls_name == "dns.google"
    invalid = cli_collection_policy(INVALID)
    assert invalid is not None
    assert not invalid.available


def test_cli_context_scopes_the_whole_process_including_event_loops(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RECON_DNS_VIEW", raising=False)
    with cli_collection_context():
        assert current_policy().mode == "operator"
    monkeypatch.setenv("RECON_DNS_VIEW", "caller-safe")
    with cli_collection_context():
        assert current_policy().mode == "caller-safe"

        async def observed() -> str:
            return current_policy().mode

        assert asyncio.run(observed()) == "caller-safe"
    assert current_policy().mode == "operator"


@pytest.mark.asyncio
async def test_unusable_view_refuses_before_any_collector(monkeypatch: pytest.MonkeyPatch) -> None:
    async def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("collection ran under an unusable DNS view")

    monkeypatch.setattr(resolver, "_resolve_tenant_inner", forbidden)
    with collection_scope(CollectionPolicy("caller-safe", available=False)), pytest.raises(ReconLookupError) as caught:
        await resolver.resolve_tenant("example.com")
    assert caught.value.error_type == "dns_view_unavailable"


@patch(RESOLVE_PATH, new_callable=AsyncMock)
def test_lookup_reports_an_unusable_view_as_input_error(mock_resolve: AsyncMock) -> None:
    mock_resolve.side_effect = ReconLookupError(
        domain="example.com", message="The encrypted DNS view is disabled", error_type="dns_view_unavailable"
    )
    result = runner.invoke(app, ["example.com", "--no-cache"])
    assert result.exit_code == 2
    assert GUIDE in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize(
    ("policy", "hinted"), [(None, False), (CollectionPolicy("caller-safe", ("1.1.1.1",), "cloudflare-dns.com"), True)]
)
@patch(RESOLVE_PATH, new_callable=AsyncMock)
def test_total_failure_hints_at_blocked_encrypted_dns_only_when_opted_in(
    mock_resolve: AsyncMock, policy: CollectionPolicy | None, hinted: bool
) -> None:
    mock_resolve.side_effect = ReconLookupError(
        domain="example.com", message="every source failed", error_type="all_sources_failed"
    )
    if policy is None:
        result = runner.invoke(app, ["example.com", "--no-cache"])
    else:
        with collection_scope(policy):
            result = runner.invoke(app, ["example.com", "--no-cache"])
    assert result.exit_code == 4
    assert ("Encrypted DNS is on" in result.stderr) is hinted
    # Links wrap only at word boundaries, so the URL survives intact.
    assert (GUIDE in result.stderr) is hinted
    assert "cloudflare-dns.com" not in result.stderr


@pytest.mark.parametrize("command", [["review", "example.com"], ["batch", "-"]])
def test_multi_step_commands_refuse_an_unusable_view_before_work(command: list[str]) -> None:
    with (
        collection_scope(CollectionPolicy("caller-safe", available=False)),
        patch(RESOLVE_PATH, new_callable=AsyncMock) as mock_resolve,
    ):
        result = runner.invoke(app, command, input="example.com\n")
    assert result.exit_code == 2
    assert GUIDE in result.stderr
    mock_resolve.assert_not_called()


@pytest.mark.parametrize(
    "command",
    [
        ["example.com", "--no-cache"],
        ["example.com", "--chain"],
        ["discover", "example.com"],
        ["review", "example.com"],
        ["batch", "-"],
        ["capsule", "capture", "example.com"],
    ],
)
def test_installed_entry_point_refuses_offline_and_keeps_offline_commands(tmp_path: Path, command: list[str]) -> None:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("RECON_")}
    environment.update(INVALID, RECON_CONFIG_DIR=str(tmp_path))

    def recon(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed interpreter argv, no shell.
            [sys.executable, "-c", "from recon_tool.cli import run; run()", *args],
            env=environment,
            cwd=tmp_path,
            input="example.com\n",
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    refused = recon(*command)
    assert refused.returncode == 2, refused.stderr
    assert "RECON_DNS_* settings are invalid" in refused.stderr
    assert "Traceback" not in refused.stderr
    assert recon("--version").returncode == 0
