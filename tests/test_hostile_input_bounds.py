"""Per-parser resource-bound assertions + hostile-input fuzz (the CI fuzz gate).

Each parser at an external boundary carries a named resource cap. The unit and
property tests here drive crafted oversized / flooded / malformed input straight
at the parser and assert the cap holds, so the bound is enforced against a future
refactor rather than only documented in a constant. The whole module is marked
``hostile_input`` so the dedicated ``hostile-input-fuzz`` CI job can run it (and
the Hypothesis suites at a higher example budget) as an authoritative gate,
separate from incidental coverage under the generic test job.

Covered caps: userrealm ``_MAX_AUTODISCOVER_DOMAINS`` and the defusedxml
entity-expansion / external-entity guard; crt.sh ``_MAX_SANS_PER_CERT`` and
``_MAX_CRTSH_CERT_SUMMARY_ENTRIES``; the CT burst / wildcard-cluster caps; the
SPF redirect depth bound; and the DMARC rua extraction under a mailto flood.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from hypothesis import given
from hypothesis import strategies as st

from recon_tool.sources import dns as dns_mod
from recon_tool.sources.cert_providers import (
    _MAX_BURSTS,
    _MAX_CRTSH_CERT_SUMMARY_ENTRIES,
    _MAX_NAMES_PER_BURST,
    _MAX_NAMES_PER_CLUSTER,
    _MAX_SANS_PER_CERT,
    _MAX_WILDCARD_CLUSTERS,
    _detect_deployment_bursts,
    _extract_crtsh_entries,
    _extract_wildcard_sibling_clusters,
)
from recon_tool.sources.userrealm import _MAX_AUTODISCOVER_DOMAINS, _parse_autodiscover_domains

pytestmark = pytest.mark.hostile_input


# ── userrealm Autodiscover XML ────────────────────────────────────────────


def _autodiscover_xml(domains: list[str]) -> str:
    body = "".join(f"<Domain>{d}</Domain>" for d in domains)
    return f'<?xml version="1.0"?><Response xmlns="http://x">{body}</Response>'


class TestAutodiscoverBounds:
    def test_domain_flood_is_capped(self) -> None:
        xml = _autodiscover_xml([f"d{i}.contoso.com" for i in range(5000)])
        domains, _default = _parse_autodiscover_domains(xml)
        assert len(domains) <= _MAX_AUTODISCOVER_DOMAINS

    def test_billion_laughs_is_refused_not_expanded(self) -> None:
        bomb = (
            '<?xml version="1.0"?>'
            "<!DOCTYPE lolz ["
            '<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
            "]>"
            "<Response><Domain>&lol3;</Domain></Response>"
        )
        # defusedxml refuses entity expansion; the parser degrades to empty.
        assert _parse_autodiscover_domains(bomb) == ([], None)

    def test_external_entity_xxe_is_refused(self) -> None:
        xxe = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE r [<!ENTITY ext SYSTEM "file:///etc/passwd">]>'
            "<Response><Domain>&ext;</Domain></Response>"
        )
        assert _parse_autodiscover_domains(xxe) == ([], None)

    def test_malformed_xml_degrades(self) -> None:
        assert _parse_autodiscover_domains("<Response><Domain>not closed") == ([], None)

    @given(st.text(max_size=4000))
    def test_never_raises_on_arbitrary_text(self, text: str) -> None:
        domains, default = _parse_autodiscover_domains(text)
        assert isinstance(domains, list)
        assert default is None or isinstance(default, str)


# ── crt.sh payload parsing ────────────────────────────────────────────────


class TestCrtshEntryBounds:
    def test_per_cert_san_flood_is_capped(self) -> None:
        name_value = "\n".join(f"h{i}.contoso.com" for i in range(5000))
        cert = {
            "name_value": name_value,
            "issuer_ca_id": 1,
            "issuer_name": "Fabrikam CA",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
        }
        _raw, cert_entries = _extract_crtsh_entries([cert])
        assert cert_entries
        dns_names = cert_entries[0]["dns_names"]
        assert isinstance(dns_names, list)
        assert len(dns_names) <= _MAX_SANS_PER_CERT

    def test_entry_flood_is_capped(self) -> None:
        certs = [
            {
                "name_value": f"h{i}.contoso.com",
                "issuer_ca_id": 1,
                "issuer_name": "Fabrikam CA",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00",
            }
            for i in range(5000)
        ]
        _raw, cert_entries = _extract_crtsh_entries(certs)
        assert len(cert_entries) <= _MAX_CRTSH_CERT_SUMMARY_ENTRIES

    def test_single_newline_free_giant_name_is_bounded(self) -> None:
        # One ~1 MB name_value with no newline: the field is sliced before the
        # per-character DNS-name scan, so this must not hang or explode.
        cert = {
            "name_value": "a" * (1024 * 1024),
            "issuer_ca_id": 1,
            "issuer_name": "Fabrikam CA",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
        }
        raw, cert_entries = _extract_crtsh_entries([cert])
        assert isinstance(raw, list)
        assert cert_entries

    @given(
        st.lists(
            st.dictionaries(
                st.sampled_from(["name_value", "issuer_ca_id", "issuer_name", "not_before", "not_after"]),
                st.one_of(st.text(max_size=200), st.integers(), st.none()),
                max_size=5,
            ),
            max_size=40,
        )
    )
    def test_never_raises_on_arbitrary_entries(self, data: list[dict[str, Any]]) -> None:
        raw, cert_entries = _extract_crtsh_entries(data)  # type: ignore[arg-type]
        assert isinstance(raw, list)
        assert isinstance(cert_entries, list)


# ── CT burst / wildcard-cluster grouping ──────────────────────────────────


class TestCtGroupingBounds:
    def test_burst_count_capped_across_many_windows(self) -> None:
        # 50 windows, each > _BURST_WINDOW_SECONDS apart, each a 3-name cohort.
        entries = []
        for w in range(50):
            ts = f"2026-01-01T00:{w * 2:02d}:00+00:00"
            entries.append({"not_before": ts, "dns_names": [f"w{w}-a.com", f"w{w}-b.com", f"w{w}-c.com"]})
        bursts = _detect_deployment_bursts(entries)
        assert len(bursts) <= _MAX_BURSTS

    def test_names_per_burst_capped(self) -> None:
        entries = [{"not_before": "2026-01-01T00:00:00+00:00", "dns_names": [f"n{i}.com" for i in range(500)]}]
        bursts = _detect_deployment_bursts(entries)
        for burst in bursts:
            assert len(burst.names) <= _MAX_NAMES_PER_BURST

    def test_wildcard_clusters_capped(self) -> None:
        # 50 distinct wildcard certs => 50 candidate clusters, capped to the max.
        entries = [{"dns_names": ["*.x.com", f"c{c}-only.com", f"c{c}-also.com", f"c{c}-third.com"]} for c in range(50)]
        clusters = _extract_wildcard_sibling_clusters(entries)
        assert len(clusters) <= _MAX_WILDCARD_CLUSTERS

    def test_names_per_wildcard_cluster_capped(self) -> None:
        entries = [{"dns_names": ["*.x.com", *[f"s{i}.com" for i in range(500)]]}]
        clusters = _extract_wildcard_sibling_clusters(entries)
        for cluster in clusters:
            assert len(cluster) <= _MAX_NAMES_PER_CLUSTER


# ── DNS parsers: SPF redirect depth + DMARC rua flood ─────────────────────


class TestDnsParserBounds:
    @pytest.mark.asyncio
    async def test_spf_redirect_loop_terminates(self) -> None:
        """A self-referencing SPF redirect chain is bounded by max_depth, so the
        number of resolver queries stays small instead of looping forever."""
        calls: list[str] = []

        async def _fake_resolve(domain: str, rdtype: str, timeout: float = 5.0) -> list[str]:
            calls.append(domain)
            # Always answer with another redirect to a public target.
            return ["v=spf1 redirect=_spf.fabrikam.com"]

        ctx = dns_mod._DetectionCtx()
        with patch.object(dns_mod, "_safe_resolve", _fake_resolve):
            await dns_mod._follow_spf_redirect(ctx, "v=spf1 redirect=_spf.fabrikam.com", depth=0, max_depth=3)
        # depth 0 starts the walk; at most max_depth resolver queries follow.
        assert len(calls) <= 3

    def test_dmarc_rua_mailto_flood_is_bounded(self) -> None:
        """A DMARC record with thousands of rua mailto addresses parses without
        crashing; the work is bounded by the (DNS-ceiling-bounded) record."""
        addrs = ",".join(f"mailto:a{i}@dmarc.fabrikam.com" for i in range(2000))
        record = f"v=DMARC1; p=reject; rua={addrs}"
        ctx = dns_mod._DetectionCtx()
        # Must complete and not raise; the rua matcher is linear in the record.
        dns_mod._extract_dmarc_rua(ctx, record)
