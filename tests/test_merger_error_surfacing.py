"""R2 tests — ReconLookupError surfaces per-source failure reasons.

When every source fails transiently and the merger can't produce a
TenantInfo, the raised exception carries per-source error strings so the
CLI and library callers can distinguish "domain is truly empty" from
"every source had a transient failure". Before v0.9.2 the message was a
single generic string.
"""

from __future__ import annotations

import pytest

from recon_tool.merger import merge_results
from recon_tool.models import ReconLookupError, SourceResult


def _failed(name: str, error: str) -> SourceResult:
    return SourceResult(source_name=name, error=error)


class TestReconLookupErrorSourceErrors:
    """Verify the raised exception carries the per-source errors."""

    def test_all_sources_failed_with_errors_includes_reasons(self) -> None:
        """When every source returns an error, the exception carries them."""
        results = [
            _failed("oidc_discovery", "HTTP 429 from OIDC discovery endpoint"),
            _failed("user_realm", "Could not resolve display name"),
            _failed("google_identity", "Network error: ConnectError('reset')"),
            _failed("dns_records", "DNS error for example.com: TimeoutError"),
        ]
        with pytest.raises(ReconLookupError) as excinfo:
            merge_results(results, "example.com")

        err = excinfo.value
        assert err.error_type == "all_sources_failed"
        assert err.domain == "example.com"
        # Exactly one entry per failed source
        assert len(err.source_errors) == 4
        names = {n for n, _ in err.source_errors}
        assert names == {"oidc_discovery", "user_realm", "google_identity", "dns_records"}
        # Each message is preserved verbatim
        oidc_error = next(msg for n, msg in err.source_errors if n == "oidc_discovery")
        assert "429" in oidc_error

    def test_error_message_includes_source_reasons(self) -> None:
        """The message string includes all source reasons joined by '; '."""
        results = [
            _failed("oidc_discovery", "HTTP 429"),
            _failed("dns_records", "no records found"),
        ]
        with pytest.raises(ReconLookupError) as excinfo:
            merge_results(results, "example.com")

        msg = str(excinfo.value)
        assert "oidc_discovery: HTTP 429" in msg
        assert "dns_records: no records found" in msg

    def test_all_sources_empty_no_errors_uses_generic_message(self) -> None:
        """When sources returned without errors but nothing detected, the
        exception uses a neutral message saying the domain looks empty."""
        results = [
            SourceResult(source_name="oidc_discovery"),
            SourceResult(source_name="dns_records"),
        ]
        with pytest.raises(ReconLookupError) as excinfo:
            merge_results(results, "example.com")

        msg = str(excinfo.value)
        assert "no public DNS records matching any fingerprint" in msg
        assert excinfo.value.source_errors == ()


class TestPartialSuccessStillRenders:
    """When any source produced at least one detected service, the merger
    should NOT raise even if tenant_id is unknown. This is the partial-
    success path — a domain with no M365 tenant but some DNS services is
    still worth rendering.
    """

    def test_services_only_no_tenant_returns_partial(self) -> None:
        """Services detected + no tenant → returns a TenantInfo, doesn't raise."""
        results = [
            _failed("oidc_discovery", "HTTP 404"),
            SourceResult(
                source_name="dns_records",
                detected_services=("Cloudflare", "DMARC"),
                detected_slugs=("cloudflare", "dmarc"),
            ),
        ]
        info = merge_results(results, "example.com")
        assert info.tenant_id is None
        assert "Cloudflare" in info.services
        assert info.queried_domain == "example.com"

    def test_partial_success_renders_through_cli(self) -> None:
        """Phase 2e end-to-end: the CLI should render a panel for a
        partial-success TenantInfo (some services, no tenant_id) and
        exit 0, not produce a "No information found" warning."""
        from unittest.mock import patch

        from typer.testing import CliRunner

        from recon_tool.cli import app
        from recon_tool.models import ConfidenceLevel, TenantInfo

        partial_info = TenantInfo(
            tenant_id=None,
            display_name="example.com",
            default_domain="example.com",
            queried_domain="example.com",
            confidence=ConfidenceLevel.LOW,
            region="",
            sources=("dns_records",),
            services=("Cloudflare", "DMARC"),
            slugs=("cloudflare", "dmarc"),
            auth_type=None,
            dmarc_policy="reject",
            domain_count=1,
        )
        partial_results = [
            SourceResult(source_name="oidc_discovery", error="HTTP 404"),
            SourceResult(
                source_name="dns_records",
                detected_services=("Cloudflare", "DMARC"),
                detected_slugs=("cloudflare", "dmarc"),
                dmarc_policy="reject",
            ),
        ]

        async def fake_resolve(*args: object, **kwargs: object):
            return partial_info, partial_results

        runner = CliRunner()
        with patch("recon_tool.resolver.resolve_tenant", side_effect=fake_resolve):
            result = runner.invoke(app, ["lookup", "example.com", "--no-cache"])

        assert result.exit_code == 0
        assert "Cloudflare" in result.stdout
        assert "No information found" not in result.stdout
