"""v1.9.3.5 - CNAME chain target validation regression tests.

Pins the two-layer attacker-controlled-target defense in
``recon_tool.sources.dns._resolve_cname_chain``:

  1. Suffix denylist via ``_is_public_dns_name`` - catches hops whose
     name ends in obvious private suffixes (``.local``, ``.corp``,
     ``.internal``, ``.home.arpa``, etc.) and IP literals.

  2. Resolved-address check via ``_hop_resolves_publicly`` - for hops
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
            # v1.9.13: character-class restrictions - adversarial DNS
            # responses or lax resolvers could otherwise smuggle these
            # to evidence output.
            "evil<script>.com",
            "name with space.com",
            "name\tab.com",
            "name\nnewline.com",
            "name;semicolon.com",
            "name&amp.com",
            "ñoño.example.com",  # non-ASCII (legitimate IDN uses Punycode)
            "name|pipe.com",
            "name`backtick.com",
            "name$dollar.com",
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
            # v1.9.13: legitimate DKIM / SRV selectors use underscore.
            "selector1._domainkey.contoso.com",
            "_sipfederationtls._tcp.contoso.com",
            # v1.9.13: Punycode IDN names use ASCII LDH only.
            "xn--p1ai.example.com",
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
        # facing - the operator's resolver query is reaching public space,
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
    async def test_walker_does_not_resolve_a_aaaa_on_intermediate_hops(self, monkeypatch):
        # v1.9.4 invariant: the walker MUST NOT issue A/AAAA queries
        # on intermediate hops (entry-point or any hop other than the
        # terminus) during the walk loop. Doing so causes the
        # recursive resolver to chase deeper CNAMEs while answering,
        # potentially querying private/internal names before the
        # walker's suffix denylist has seen them.
        #
        # v1.9.13 addition: the walker MAY issue A/AAAA on the
        # terminus only, AFTER the walk has completed naturally
        # (chain[-1] has no further CNAME). That is safe (no chase
        # possible) and lets the walker drop chains whose terminus
        # resolves only to private space.
        queries_made: list[tuple[str, str]] = []
        plan: dict[tuple[str, str], list[str]] = {
            ("attacker.example.com", "CNAME"): ["split.attacker-domain.com"],
            # Terminus has a public A record so the v1.9.13 check
            # accepts the chain.
            ("split.attacker-domain.com", "A"): ["8.8.8.8"],
        }

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs) -> list[str]:
            queries_made.append((domain, rdtype))
            return list(plan.get((domain, rdtype), []))

        monkeypatch.setattr(dns_mod, "_safe_resolve", _tracking_resolve)
        chain = await dns_mod._resolve_cname_chain("attacker.example.com")

        assert chain == ["split.attacker-domain.com"], (
            f"walker should accept a public-suffix hop; got chain={chain!r}"
        )
        # The entry-point name must NEVER be A/AAAA queried - this is
        # the v1.9.4 invariant that closes the original audit finding.
        intermediate_a_aaaa = [
            q for q in queries_made
            if q[1] in ("A", "AAAA") and q[0] == "attacker.example.com"
        ]
        assert intermediate_a_aaaa == [], (
            "v1.9.4 invariant: walker must not issue A/AAAA on "
            "intermediate or entry-point hops. A/AAAA on an "
            "attacker-influenced name causes the recursive resolver "
            "to chase deeper CNAMEs internally, potentially querying "
            f"private names. Got: {intermediate_a_aaaa!r}"
        )
        # v1.9.13: any A/AAAA queries issued must target the terminus only.
        a_aaaa_targets = {q[0] for q in queries_made if q[1] in ("A", "AAAA")}
        assert a_aaaa_targets <= {"split.attacker-domain.com"}, (
            "v1.9.13 invariant: A/AAAA may target only the terminus, "
            f"not intermediate hops. Got targets: {a_aaaa_targets!r}"
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


# ── v1.9.13: entry-point validation ────────────────────────────────


class TestEntryPointValidation:
    """v1.9.13: the walker validates the entry-point name before
    issuing any DNS query. Catches private-suffix entries that some
    related_domains populators might leak in.
    """

    @pytest.mark.asyncio
    async def test_private_suffix_entry_point_returns_empty_no_queries(self, monkeypatch):
        queries_made: list[tuple[str, str]] = []

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            queries_made.append((domain, rdtype))
            return []

        monkeypatch.setattr(dns_mod, "_safe_resolve", _tracking_resolve)
        chain = await dns_mod._resolve_cname_chain("internal.corp")
        assert chain == [], f"private-suffix entry point should return empty chain; got {chain!r}"
        assert queries_made == [], (
            f"walker must not issue any DNS query on a private-suffix entry point; "
            f"got queries={queries_made!r}"
        )

    @pytest.mark.asyncio
    async def test_ip_literal_entry_point_returns_empty_no_queries(self, monkeypatch):
        queries_made: list[tuple[str, str]] = []

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            queries_made.append((domain, rdtype))
            return []

        monkeypatch.setattr(dns_mod, "_safe_resolve", _tracking_resolve)
        chain = await dns_mod._resolve_cname_chain("10.0.0.1")
        assert chain == []
        assert queries_made == [], f"got queries={queries_made!r}"

    @pytest.mark.asyncio
    async def test_single_label_entry_point_returns_empty_no_queries(self, monkeypatch):
        queries_made: list[tuple[str, str]] = []

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            queries_made.append((domain, rdtype))
            return []

        monkeypatch.setattr(dns_mod, "_safe_resolve", _tracking_resolve)
        chain = await dns_mod._resolve_cname_chain("hostname")
        assert chain == []
        assert queries_made == []

    @pytest.mark.asyncio
    async def test_mixed_case_entry_point_normalized_for_self_loop_detection(self, monkeypatch):
        # v1.9.13: host is lowercased at entry so a self-loop is
        # detected on the first iteration regardless of input case.
        # Without normalization, "Attacker.example.com" CNAME ->
        # "attacker.example.com" would NOT match the
        # ``target == cur`` self-loop check on iteration 1 (case
        # differs), and the walker would record one wasted hop
        # before detecting the loop on iteration 2.
        plan: dict[tuple[str, str], list[str]] = {
            ("attacker.example.com", "CNAME"): ["attacker.example.com"],  # self-loop
        }
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        chain = await dns_mod._resolve_cname_chain("Attacker.example.com")
        # Self-loop detected immediately; no hops recorded.
        assert chain == [], (
            f"case-mismatched self-loop should be detected without recording a hop; "
            f"got chain={chain!r}"
        )


# ── v1.9.13: terminus-only A/AAAA check ────────────────────────────


class TestTerminusOnlyAAAACheck:
    """v1.9.13: after the walk completes naturally, the walker
    resolves A/AAAA on the terminus only and drops the chain when
    every resolved address is in private space. The check runs only
    on the natural-exit path; max_hops and suffix-rejection exits
    skip the check (terminus has unfollowed CNAME → recursive chase
    would re-introduce the v1.9.4 leak).
    """

    @pytest.mark.asyncio
    async def test_drops_chain_with_all_private_terminus(self, monkeypatch):
        plan: dict[tuple[str, str], list[str]] = {
            ("attacker.example.com", "CNAME"): ["hop1.attacker.example.com"],
            ("hop1.attacker.example.com", "CNAME"): ["terminus.something.com"],
            # Terminus has no further CNAME → natural exit.
            ("terminus.something.com", "A"): ["10.0.0.5"],
            ("terminus.something.com", "AAAA"): ["fc00::1"],
        }
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        chain = await dns_mod._resolve_cname_chain("attacker.example.com")
        assert chain == [], (
            f"chain whose terminus resolves only to private space must be dropped entirely; "
            f"got {chain!r}"
        )

    @pytest.mark.asyncio
    async def test_keeps_chain_with_public_terminus(self, monkeypatch):
        plan: dict[tuple[str, str], list[str]] = {
            ("contoso.com", "CNAME"): ["contoso.azurewebsites.net"],
            ("contoso.azurewebsites.net", "A"): ["20.50.2.50"],
            ("contoso.azurewebsites.net", "AAAA"): [],
        }
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        chain = await dns_mod._resolve_cname_chain("contoso.com")
        assert chain == ["contoso.azurewebsites.net"]

    @pytest.mark.asyncio
    async def test_keeps_chain_with_dangling_terminus_no_a_records(self, monkeypatch):
        # Terminus has no A or AAAA records (dangling CNAME). The
        # check is fail-open: we don't know whether the terminus is
        # public or private, so we keep the chain. Many real targets
        # have CNAME-only terminuses with no direct A record.
        plan: dict[tuple[str, str], list[str]] = {
            ("apex.example.com", "CNAME"): ["dangling.example.com"],
        }
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        chain = await dns_mod._resolve_cname_chain("apex.example.com")
        assert chain == ["dangling.example.com"]

    @pytest.mark.asyncio
    async def test_keeps_chain_with_mixed_public_and_private_terminus(self, monkeypatch):
        # At least one public address → keep. Mirrors
        # _hop_resolves_publicly's "any public" semantics.
        plan: dict[tuple[str, str], list[str]] = {
            ("apex.example.com", "CNAME"): ["mixed.example.com"],
            ("mixed.example.com", "A"): ["10.0.0.5", "8.8.8.8"],
            ("mixed.example.com", "AAAA"): [],
        }
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        chain = await dns_mod._resolve_cname_chain("apex.example.com")
        assert chain == ["mixed.example.com"]

    @pytest.mark.asyncio
    async def test_skips_terminus_check_when_max_hops_hit(self, monkeypatch):
        # Walker hits max_hops with the last recorded hop still
        # having an unfollowed CNAME. A recursive A/AAAA query on
        # that hop would chase the unfollowed CNAME - re-introducing
        # the v1.9.4 leak. Walker MUST NOT do the terminus check.
        queries_made: list[tuple[str, str]] = []
        plan: dict[tuple[str, str], list[str]] = {
            ("h0.example.com", "CNAME"): ["h1.example.com"],
            ("h1.example.com", "CNAME"): ["h2.example.com"],
            ("h2.example.com", "CNAME"): ["h3.example.com"],
            ("h3.example.com", "CNAME"): ["h4.example.com"],
            ("h4.example.com", "CNAME"): ["h5.example.com"],
            # h5 still has a further CNAME the walker won't follow.
            ("h5.example.com", "CNAME"): ["h6.example.com"],
        }

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            queries_made.append((domain, rdtype))
            return list(plan.get((domain, rdtype), []))

        monkeypatch.setattr(dns_mod, "_safe_resolve", _tracking_resolve)
        chain = await dns_mod._resolve_cname_chain("h0.example.com")
        assert chain == [
            "h1.example.com",
            "h2.example.com",
            "h3.example.com",
            "h4.example.com",
            "h5.example.com",
        ]
        non_cname = [q for q in queries_made if q[1] != "CNAME"]
        assert non_cname == [], (
            "walker must NOT issue A/AAAA after a max_hops exit "
            "(terminus may have an unfollowed CNAME, causing recursive chase). "
            f"Got: {non_cname!r}"
        )

    @pytest.mark.asyncio
    async def test_skips_terminus_check_after_suffix_rejection(self, monkeypatch):
        # Walker breaks on suffix rejection. The current name has a
        # CNAME to the rejected private target. A recursive A/AAAA
        # query on cur would chase to the rejected target.
        queries_made: list[tuple[str, str]] = []
        plan: dict[tuple[str, str], list[str]] = {
            ("apex.example.com", "CNAME"): ["edge.fastly.net"],
            ("edge.fastly.net", "CNAME"): ["origin.attacker.corp"],
        }

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            queries_made.append((domain, rdtype))
            return list(plan.get((domain, rdtype), []))

        monkeypatch.setattr(dns_mod, "_safe_resolve", _tracking_resolve)
        chain = await dns_mod._resolve_cname_chain("apex.example.com")
        assert chain == ["edge.fastly.net"]
        non_cname = [q for q in queries_made if q[1] != "CNAME"]
        assert non_cname == [], (
            "walker must NOT issue A/AAAA after a suffix-rejection break "
            "(current name has CNAME to rejected private target). "
            f"Got: {non_cname!r}"
        )


# ── v1.9.13: _detect_m365_cnames redirect_domain filter ────────────


class TestM365RedirectDomainFilter:
    """v1.9.13: _detect_m365_cnames suffix-validates the
    redirect_domain extracted from a non-Microsoft autodiscover
    CNAME before adding it to related_domains. Defense-in-depth
    against an attacker-controlled autodiscover response that would
    otherwise plant a private-suffix apex in related_domains.
    """

    @pytest.mark.asyncio
    async def test_private_suffix_redirect_domain_dropped(self, monkeypatch):
        # autodiscover.attacker.example -> something.internal.corp
        # redirect_domain = "internal.corp" (private suffix) → drop.
        plan: dict[tuple[str, str], list[str]] = {
            ("autodiscover.attacker.example", "CNAME"): ["something.internal.corp"],
        }

        async def _stub(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            return list(plan.get((domain, rdtype), []))

        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub)
        ctx = dns_mod._DetectionCtx()
        await dns_mod._detect_m365_cnames(ctx, "attacker.example")
        assert "internal.corp" not in ctx.related_domains, (
            f"private-suffix redirect_domain must not be added to related_domains; "
            f"got related_domains={ctx.related_domains!r}"
        )

    @pytest.mark.asyncio
    async def test_public_suffix_redirect_domain_still_added(self, monkeypatch):
        # autodiscover.legit.example -> mail.partner.com
        # redirect_domain = "partner.com" (public) → still added.
        # The v1.9.13 filter is a defense-in-depth tightening, not
        # a behavioral change for legitimate cross-apex chains.
        plan: dict[tuple[str, str], list[str]] = {
            ("autodiscover.legit.example", "CNAME"): ["mail.partner.com"],
        }

        async def _stub(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            return list(plan.get((domain, rdtype), []))

        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub)
        ctx = dns_mod._DetectionCtx()
        await dns_mod._detect_m365_cnames(ctx, "legit.example")
        assert "partner.com" in ctx.related_domains
