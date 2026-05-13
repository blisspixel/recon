"""v1.9.3.5 — CNAME chain target validation regression tests.

Pins the two-layer attacker-controlled-target defense in
``recon_tool.sources.dns._resolve_cname_chain``:

  1. Suffix denylist via ``_is_public_dns_name`` — catches hops whose
     name ends in obvious private suffixes (``.local``, ``.corp``,
     ``.internal``, ``.home.arpa``, etc.) and IP literals.

  2. Resolved-address check via ``_hop_resolves_publicly`` — for hops
     that pass the suffix check, resolves A and AAAA records and
     refuses to walk further when every resolved address is in
     private / loopback / link-local / reserved space.

The audit finding ("CNAME chain walking can query and leak internal
DNS names", MEDIUM) covers the case where attacker-controlled public
DNS returns a CNAME to an internal split-horizon name. Layer 1
catches the easy case (clearly-internal name); layer 2 catches the
harder case (publicly-named host that happens to resolve into
private space via split-horizon).

These tests stub ``_safe_resolve`` so the walker sees deterministic
DNS answers without making real network calls.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from recon_tool.sources import dns as dns_mod

# ── Layer 1: suffix denylist ───────────────────────────────────────


class TestPublicDnsNameSuffix:
    """``_is_public_dns_name`` returns False for any obviously-private
    name, IP literal, or single-label."""

    @pytest.mark.parametrize(
        "name",
        [
            "internal.corp",
            "host.lan",
            "server.local",
            "backend.intranet",
            "node.private",
            "machine.home.arpa",
            "service.test",
            "demo.example",
            "broken.invalid",
            "facebookcorewwwi.onion",
            "10.in-addr.arpa",
            "1.0.168.192.in-addr.arpa",
            "broken.ip6.arpa",
            "10.0.0.1",  # IPv4 literal
            "fe80::1",  # IPv6 literal
            "hostname",  # single-label
            "",
        ],
    )
    def test_rejects_private_and_malformed(self, name):
        assert dns_mod._is_public_dns_name(name) is False, f"{name!r} should NOT be classified as public DNS"

    @pytest.mark.parametrize(
        "name",
        [
            "example.com",
            "edge.fastly.net",
            "tenant.azurewebsites.net",
            "dx-12345.cloudfront.net",
            "deep.subdomain.contoso.com",
        ],
    )
    def test_accepts_obviously_public(self, name):
        assert dns_mod._is_public_dns_name(name) is True, f"{name!r} should be classified as public DNS"


# ── Layer 2: resolved-address private check ────────────────────────


class TestPrivateIpLiteralCheck:
    """``_is_private_ip_literal`` returns True for RFC1918, loopback,
    link-local, and ULA addresses; False for public addresses and for
    anything unparseable."""

    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",  # link-local
            "0.0.0.0",  # unspecified  # noqa: S104
            "fc00::1",  # ULA
            "fe80::1",  # link-local v6
            "::1",  # loopback v6
            "224.0.0.1",  # multicast
        ],
    )
    def test_recognizes_private_addresses(self, ip):
        assert dns_mod._is_private_ip_literal(ip) is True, f"{ip} should be classified as private"

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "151.101.1.10",
            "2606:4700:4700::1111",  # public IPv6 (Cloudflare)
        ],
    )
    def test_recognizes_public_addresses(self, ip):
        assert dns_mod._is_private_ip_literal(ip) is False, f"{ip} should be classified as public"

    @pytest.mark.parametrize("garbage", ["not-an-ip", "999.999.999.999", "", "::xyz::"])
    def test_unparseable_returns_false(self, garbage):
        # Defensive: garbage gets treated as not-private so the caller
        # falls back to other checks.
        assert dns_mod._is_private_ip_literal(garbage) is False


# ── _hop_resolves_publicly ─────────────────────────────────────────


def _stub_safe_resolve(plan: dict[tuple[str, str], list[str]]) -> Callable[..., Any]:
    """Build a monkeypatch replacement for ``_safe_resolve``.

    ``plan`` maps (host, rdtype) → list of records. Anything not in the
    plan returns an empty list (mirroring real ``_safe_resolve``'s
    fail-empty contract).
    """

    async def fake(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
        return list(plan.get((domain, rdtype), []))

    return fake


class TestHopResolvesPublicly:
    """The hop-classification helper that the walker uses."""

    @pytest.mark.asyncio
    async def test_public_a_record_returns_true(self, monkeypatch):
        monkeypatch.setattr(
            dns_mod,
            "_safe_resolve",
            _stub_safe_resolve({("host.example.com", "A"): ["151.101.1.10"]}),
        )
        assert await dns_mod._hop_resolves_publicly("host.example.com") is True

    @pytest.mark.asyncio
    async def test_all_private_addresses_returns_false(self, monkeypatch):
        monkeypatch.setattr(
            dns_mod,
            "_safe_resolve",
            _stub_safe_resolve(
                {
                    ("split-horizon.example.com", "A"): ["10.0.0.5", "10.0.0.6"],
                    ("split-horizon.example.com", "AAAA"): ["fc00::1"],
                },
            ),
        )
        assert await dns_mod._hop_resolves_publicly("split-horizon.example.com") is False, (
            "split-horizon target with only private A/AAAA records must be classified as not-publicly-resolving"
        )

    @pytest.mark.asyncio
    async def test_mixed_public_and_private_returns_true(self, monkeypatch):
        # A target with at least one public address is considered public-
        # facing — the operator's resolver query is reaching public space,
        # and the public address is the actual leak surface.
        monkeypatch.setattr(
            dns_mod,
            "_safe_resolve",
            _stub_safe_resolve(
                {
                    ("dual.example.com", "A"): ["10.0.0.5", "8.8.8.8"],
                },
            ),
        )
        assert await dns_mod._hop_resolves_publicly("dual.example.com") is True

    @pytest.mark.asyncio
    async def test_no_a_records_returns_true_fail_open(self, monkeypatch):
        # CNAME-only intermediate hops resolve to nothing on direct A
        # query. The walker must continue (next iteration's CNAME query
        # will resolve or fail naturally). "Fail open" here is correct.
        monkeypatch.setattr(
            dns_mod,
            "_safe_resolve",
            _stub_safe_resolve({}),
        )
        assert await dns_mod._hop_resolves_publicly("cname-only.example.com") is True


# ── Chain walker integration ───────────────────────────────────────


class TestResolveCnameChainBlocksPrivateTargets:
    """End-to-end: the walker drops attacker-controlled CNAME hops that
    target private space, by either suffix or resolved-address path."""

    @pytest.mark.asyncio
    async def test_walker_drops_suffix_private_target(self, monkeypatch):
        # attacker.example.com CNAME -> internal.corp.
        # Suffix check rejects internal.corp. Walker halts immediately.
        plan: dict[tuple[str, str], list[str]] = {
            ("attacker.example.com", "CNAME"): ["internal.corp"],
        }
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        chain = await dns_mod._resolve_cname_chain("attacker.example.com")
        assert chain == [], f"walker should not record a hop whose suffix marks it as private; got chain={chain!r}"

    @pytest.mark.asyncio
    async def test_walker_does_not_resolve_a_aaaa_during_walk(self, monkeypatch):
        # v1.9.4: the walker uses suffix-only defense. It does NOT
        # call A/AAAA on intermediate hops, because doing so would
        # cause the recursive resolver to chase deeper CNAMEs while
        # answering — potentially querying private/internal names
        # *before* this walker has applied its suffix denylist to
        # those deeper hops.
        #
        # This test asserts the walker accepts a public-suffix hop
        # whose A records (if any) we don't even ask about. The
        # split-horizon protection v1.9.3.5 added was removed in
        # v1.9.4 specifically because it required the dangerous
        # A/AAAA call. The cost: we no longer detect public-suffix
        # names that resolve to private IPs via split-horizon DNS.
        # The benefit: zero internal-DNS leakage from the walker.
        queries_made: list[tuple[str, str]] = []
        plan: dict[tuple[str, str], list[str]] = {
            ("attacker.example.com", "CNAME"): ["split.attacker-domain.com"],
            # NOTE: no A or AAAA records in the plan. If the walker
            # asked for them, the stub would still return [] and the
            # walker would (correctly) accept the hop — but we want
            # to confirm the walker DOES NOT ASK at all.
        }

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs) -> list[str]:
            queries_made.append((domain, rdtype))
            return list(plan.get((domain, rdtype), []))

        monkeypatch.setattr(dns_mod, "_safe_resolve", _tracking_resolve)
        chain = await dns_mod._resolve_cname_chain("attacker.example.com")

        # Walker accepts the public-suffix hop (suffix-only defense).
        assert chain == ["split.attacker-domain.com"], f"walker should accept a public-suffix hop; got chain={chain!r}"
        # And critically: only CNAME queries were issued. No A or AAAA
        # queries during the walk — this is the v1.9.4 security
        # invariant that closes the audit finding.
        non_cname_queries = [q for q in queries_made if q[1] != "CNAME"]
        assert non_cname_queries == [], (
            "walker must issue ONLY CNAME queries during the walk. "
            f"v1.9.4 audit fix: A/AAAA on attacker-influenced names "
            "causes the recursive resolver to chase deeper CNAMEs "
            "internally, potentially querying private names before "
            f"this walker's suffix denylist sees them. Got: {non_cname_queries!r}"
        )

    @pytest.mark.asyncio
    async def test_walker_accepts_legitimate_public_chain(self, monkeypatch):
        # contoso.com CNAME -> contoso.azurewebsites.net (public, public A)
        # azurewebsites.net resolves to a public Microsoft IP.
        plan: dict[tuple[str, str], list[str]] = {
            ("contoso.com", "CNAME"): ["contoso.azurewebsites.net"],
            ("contoso.azurewebsites.net", "A"): ["20.50.2.50"],
            ("contoso.azurewebsites.net", "AAAA"): [],
        }
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        chain = await dns_mod._resolve_cname_chain("contoso.com")
        assert chain == ["contoso.azurewebsites.net"], (
            f"walker should follow a legitimate public CNAME; got chain={chain!r}"
        )

    @pytest.mark.asyncio
    async def test_walker_truncates_at_first_failing_suffix(self, monkeypatch):
        # Two legitimate public hops, then an attacker hop pointing at
        # a clearly-private suffix. The walker records the two
        # legitimate hops but rejects the malicious one by suffix
        # denylist (no A/AAAA call needed).
        plan: dict[tuple[str, str], list[str]] = {
            ("apex.example.com", "CNAME"): ["edge.fastly.net"],
            ("edge.fastly.net", "CNAME"): ["origin.attacker.corp"],
        }
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        chain = await dns_mod._resolve_cname_chain("apex.example.com")
        # First hop (edge.fastly.net) passes suffix; second hop
        # (origin.attacker.corp) fails suffix (private .corp). Walker
        # halts there.
        assert chain == ["edge.fastly.net"], (
            f"walker should keep legitimate hops up to but not including "
            f"the first suffix-failing hop; got chain={chain!r}"
        )
