"""Tests for centralized observation-channel availability."""

from __future__ import annotations

import pytest

from recon_tool.source_status import SourceStatus


@pytest.mark.parametrize("marker", ["dns", "dns_records"])
def test_whole_dns_markers_disable_every_known_channel(marker: str) -> None:
    status = SourceStatus.from_degraded_sources((marker,))

    assert status.whole_dns_unavailable is True
    assert status.unavailable_channels == frozenset(
        {
            "dmarc",
            "dkim",
            "mta_sts",
            "bimi",
            "tls_rpt",
            "apex_txt",
            "mx",
            "caa",
            "ns",
            "cname",
            "a",
            "subdomain_txt",
            "dmarc_rua",
            "srv",
        }
    )


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ("dns:dmarc", {"dmarc"}),
        ("dns:dkim", {"dkim"}),
        ("dns:mta_sts", {"mta_sts"}),
        ("dns:bimi", {"bimi"}),
        ("dns:tls_rpt", {"tls_rpt"}),
        ("http:mta_sts_policy", {"mta_sts"}),
        ("dns:apex_txt", {"apex_txt"}),
        ("dns:mx", {"mx"}),
        ("dns:caa", {"caa"}),
        ("dns:a", {"a"}),
        ("detector:email_security", {"dmarc", "mta_sts", "bimi", "tls_rpt"}),
        ("detector:dkim", {"dkim"}),
        ("detector:caa", {"caa"}),
        ("detector:txt", {"apex_txt"}),
        ("detector:mx", {"mx"}),
        ("detector:m365_cnames", {"cname", "srv"}),
        ("detector:idp_hub", {"a", "cname"}),
        ("detector:exchange_endpoints", {"a", "cname"}),
    ],
)
def test_granular_markers_disable_only_owned_channels(marker: str, expected: set[str]) -> None:
    status = SourceStatus.from_degraded_sources((marker,))

    assert status.whole_dns_unavailable is False
    assert status.unavailable_channels == expected


def test_unknown_marker_does_not_degrade_dns_channels() -> None:
    status = SourceStatus.from_degraded_sources(("crt.sh",))

    assert status.whole_dns_unavailable is False
    assert status.unavailable_channels == frozenset()


def test_single_legacy_string_is_normalized_as_one_marker() -> None:
    status = SourceStatus.from_degraded_sources("dns")

    assert status.whole_dns_unavailable is True
