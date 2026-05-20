"""CNAME chain target validation regression tests.

Pins the chain-walker defenses in
``recon_tool.sources.dns._resolve_cname_chain``:

  1. **Entry-point validation (v1.9.13).** The walker checks
     ``_is_public_dns_name(host)`` before issuing the first CNAME
     query. Private suffixes, IP literals, and single-label names
     are rejected without touching the resolver.

  2. **Per-hop suffix denylist (v1.9.3.5).** Every CNAME target is
     validated against ``_is_public_dns_name`` before the walker
     continues. Hops with obvious private suffixes (``.local``,
     ``.corp``, ``.internal``, ``.home.arpa``, etc.) and IP literals
     are rejected.

  3. **CNAME-only walk (v1.9.4 + v1.9.14).** The walker issues only
     CNAME queries during the walk. A/AAAA queries on
     attacker-influenced names cause recursive resolvers to chase
     deeper CNAMEs, potentially querying private/internal names
     before the suffix denylist has seen them. The v1.9.13
     terminus-only A/AAAA check was reverted in v1.9.14 after a
     scanner pass showed authoritative DNS servers can return
     type-dependent answers, defeating the v1.9.13 assumption that
     a prior CNAME NoAnswer implied no chase on a subsequent A/AAAA
     query.

The audit finding ("CNAME chain walking can query and leak internal
DNS names", MEDIUM) covers the case where attacker-controlled public
DNS returns a CNAME to an internal split-horizon name.

The same internal-DNS-oracle class reaches the SPF ``redirect=``
chaser (``_follow_spf_redirect``): the owner of the queried domain
authors their own SPF record, so ``v=spf1 redirect=secret.internal.corp``
would otherwise drive the operator's resolver to an internal name.
``TestSpfRedirectBlocksPrivateTargets`` pins that the chaser reuses
the same ``_is_public_dns_name`` suffix denylist and refuses the hop
before any query.

v1.9.17 generalizes the class to every other query path. The central
guard inside ``_safe_resolve`` discards any non-CNAME/non-PTR answer
whose recursive-resolver canonical name chased a CNAME to a non-public
suffix (``TestSafeResolveCanonicalGuard``), and the A-presence probes
(IdP hub, on-prem Exchange, wildcard guard) resolve through the
CNAME-first ``_resolves_to_public_endpoint`` helper
(``TestResolvesToPublicEndpoint``).

Most tests stub ``_safe_resolve`` so the walker sees deterministic DNS
answers without real network calls; the canonical-guard tests stub the
resolver itself, because that decision lives inside ``_safe_resolve``.
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


def _stub_safe_resolve(plan: dict[tuple[str, str], list[str]]) -> Callable[..., Any]:
    """Build a monkeypatch replacement for ``_safe_resolve``.

    ``plan`` maps (host, rdtype) → list of records. Anything not in the
    plan returns an empty list (mirroring real ``_safe_resolve``'s
    fail-empty contract).
    """

    async def fake(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
        return list(plan.get((domain, rdtype), []))

    return fake


# ── Chain walker integration ───────────────────────────────────────


class TestResolveCnameChainBlocksPrivateTargets:
    """End-to-end: the walker drops attacker-controlled CNAME hops that
    target private space by suffix before issuing the next resolver query."""

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
        # v1.9.4 + v1.9.14 invariant: the walker MUST NOT issue any
        # A or AAAA queries during the walk - not on the entry point,
        # not on intermediate hops, not on the terminus. A/AAAA on an
        # attacker-influenced name causes the recursive resolver to
        # chase deeper CNAMEs while answering, potentially querying
        # private/internal names before the walker's suffix denylist
        # has seen them. v1.9.13 added a terminus-only A/AAAA check
        # on the (incorrect) assumption that a CNAME NoAnswer proved
        # no chase was possible on a subsequent A/AAAA query;
        # authoritative DNS can return type-dependent answers, so the
        # assumption does not hold. v1.9.14 reverted the check and
        # this test pins the restored invariant.
        queries_made: list[tuple[str, str]] = []
        plan: dict[tuple[str, str], list[str]] = {
            ("attacker.example.com", "CNAME"): ["split.attacker-domain.com"],
            # If the walker were to query A on the terminus, this
            # answer would be served - but the walker must not query.
            ("split.attacker-domain.com", "A"): ["8.8.8.8"],
        }

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs) -> list[str]:
            queries_made.append((domain, rdtype))
            return list(plan.get((domain, rdtype), []))

        monkeypatch.setattr(dns_mod, "_safe_resolve", _tracking_resolve)
        chain = await dns_mod._resolve_cname_chain("attacker.example.com")

        assert chain == ["split.attacker-domain.com"], f"walker should accept a public-suffix hop; got chain={chain!r}"
        a_aaaa = [q for q in queries_made if q[1] in ("A", "AAAA")]
        assert a_aaaa == [], (
            "v1.9.4 + v1.9.14 invariant: walker must not issue A/AAAA "
            "on any hop. A/AAAA on an attacker-influenced name causes "
            "the recursive resolver to chase deeper CNAMEs internally. "
            f"Got: {a_aaaa!r}"
        )

    @pytest.mark.asyncio
    async def test_walker_accepts_legitimate_public_chain(self, monkeypatch):
        # contoso.com CNAME -> contoso.azurewebsites.net (public suffix).
        plan: dict[tuple[str, str], list[str]] = {
            ("contoso.com", "CNAME"): ["contoso.azurewebsites.net"],
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


# ── SPF redirect= target validation (same internal-DNS leak class) ──


class TestSpfRedirectBlocksPrivateTargets:
    """The SPF ``redirect=`` chaser validates its target against
    ``_is_public_dns_name`` before querying. An attacker who controls
    the queried domain's SPF record (``v=spf1 redirect=<target>``) must
    not be able to drive the operator's resolver to an internal or
    split-horizon name. This is the same internal-DNS-oracle class as
    the CNAME walker, reached through a different record type.
    """

    @pytest.mark.asyncio
    async def test_private_redirect_target_is_not_queried(self, monkeypatch):
        # Attacker SPF: redirect= to an internal .corp name. The guard
        # must reject it by suffix before any resolver query, so the
        # internal name is never looked up and never credits SPF strict.
        queries_made: list[tuple[str, str]] = []

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            queries_made.append((domain, rdtype))
            # If the guard failed and the chaser queried the internal
            # name, this -all answer would wrongly credit SPF strict.
            return ["v=spf1 -all"]

        monkeypatch.setattr(dns_mod, "_safe_resolve", _tracking_resolve)
        ctx = dns_mod._DetectionCtx()
        await dns_mod._follow_spf_redirect(
            ctx,
            "v=spf1 redirect=secret.internal.corp",
            depth=0,
            max_depth=3,
        )

        assert queries_made == [], (
            f"SPF redirect chaser must not issue any query for a private-suffix target; queries={queries_made!r}"
        )
        assert dns_mod.SVC_SPF_STRICT not in ctx.services, (
            "a rejected internal redirect target must not credit SPF strict"
        )

    @pytest.mark.asyncio
    async def test_public_redirect_target_is_followed(self, monkeypatch):
        # Legitimate use (RFC 7208 6.1): redirect= to a public shared
        # SPF zone that ends in -all. The chaser follows it and credits
        # SPF strict, confirming the guard does not block normal traffic.
        plan: dict[tuple[str, str], list[str]] = {
            ("_spf.mail.contoso.com", "TXT"): [
                "v=spf1 include:spf.protection.outlook.com -all",
            ],
        }
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        ctx = dns_mod._DetectionCtx()
        await dns_mod._follow_spf_redirect(
            ctx,
            "v=spf1 redirect=_spf.mail.contoso.com",
            depth=0,
            max_depth=3,
        )
        assert dns_mod.SVC_SPF_STRICT in ctx.services, (
            "a legitimate public redirect target ending in -all must credit SPF strict"
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
            f"walker must not issue any DNS query on a private-suffix entry point; got queries={queries_made!r}"
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
        assert chain == [], f"case-mismatched self-loop should be detected without recording a hop; got chain={chain!r}"


# ── v1.9.14: CNAME-only walk invariant (no A/AAAA from the walker) ─


class TestNoAAAAQueriesFromWalker:
    """v1.9.14: the walker issues only CNAME queries. The v1.9.13
    terminus-only A/AAAA check was reverted after a 2026-05-17
    scanner pass showed authoritative DNS can return type-dependent
    answers, so a prior CNAME NoAnswer does not prove a subsequent
    A/AAAA query on the same name will not trigger a chase.
    """

    @pytest.mark.asyncio
    async def test_no_aaaa_on_natural_exit(self, monkeypatch):
        queries_made: list[tuple[str, str]] = []
        plan: dict[tuple[str, str], list[str]] = {
            ("attacker.example.com", "CNAME"): ["hop1.attacker.example.com"],
            ("hop1.attacker.example.com", "CNAME"): ["terminus.something.com"],
            # Terminus has no further CNAME → natural exit. If the
            # walker queried A here, a malicious authoritative server
            # could return a CNAME to internal space.
        }

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            queries_made.append((domain, rdtype))
            return list(plan.get((domain, rdtype), []))

        monkeypatch.setattr(dns_mod, "_safe_resolve", _tracking_resolve)
        chain = await dns_mod._resolve_cname_chain("attacker.example.com")
        assert chain == [
            "hop1.attacker.example.com",
            "terminus.something.com",
        ]
        a_aaaa = [q for q in queries_made if q[1] in ("A", "AAAA")]
        assert a_aaaa == [], f"walker must not issue A/AAAA on natural exit. Got: {a_aaaa!r}"

    @pytest.mark.asyncio
    async def test_no_aaaa_on_max_hops_exit(self, monkeypatch):
        queries_made: list[tuple[str, str]] = []
        plan: dict[tuple[str, str], list[str]] = {
            ("h0.example.com", "CNAME"): ["h1.example.com"],
            ("h1.example.com", "CNAME"): ["h2.example.com"],
            ("h2.example.com", "CNAME"): ["h3.example.com"],
            ("h3.example.com", "CNAME"): ["h4.example.com"],
            ("h4.example.com", "CNAME"): ["h5.example.com"],
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
        a_aaaa = [q for q in queries_made if q[1] in ("A", "AAAA")]
        assert a_aaaa == [], f"got: {a_aaaa!r}"

    @pytest.mark.asyncio
    async def test_no_aaaa_after_suffix_rejection(self, monkeypatch):
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
        a_aaaa = [q for q in queries_made if q[1] in ("A", "AAAA")]
        assert a_aaaa == [], f"got: {a_aaaa!r}"


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


# ── v1.9.17: _safe_resolve canonical-name guard + safe endpoint probe ──
#
# The chain-walker tests above mock _safe_resolve. The guard tests below
# mock the resolver itself, because the canonical-name decision lives
# inside _safe_resolve: for every non-CNAME/non-PTR query it discards an
# answer whose recursive-resolver canonical name chased a CNAME to a
# non-public suffix. _resolves_to_public_endpoint is the CNAME-first
# helper the A-presence probes (IdP hub, on-prem Exchange, wildcard
# guard) use so they never drive an A-query CNAME chase to an internal
# name.


class _FakeRdata:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeAnswer:
    """Minimal stand-in for ``dns.resolver.Answer``: an iterable of rdata
    plus the ``canonical_name`` the query resolved to after any CNAME
    chase the recursive resolver performed."""

    def __init__(self, canonical: str, records: list[str]) -> None:
        self.canonical_name = canonical
        self._rdata = [_FakeRdata(r) for r in records]

    def __iter__(self) -> Any:
        return iter(self._rdata)


def _fake_resolver(answer: _FakeAnswer) -> Any:
    class _Resolver:
        async def resolve(self, domain: str, rdtype: str, lifetime: float | None = None) -> _FakeAnswer:
            return answer

    return _Resolver()


class TestSafeResolveCanonicalGuard:
    """v1.9.17: ``_safe_resolve`` discards a non-CNAME/non-PTR answer
    whose recursive-resolver canonical name chased to a non-public
    suffix, so an internal name never reaches output and a private-chased
    query is indistinguishable from a name that does not resolve."""

    @pytest.mark.asyncio
    async def test_private_canonical_chase_is_discarded(self, monkeypatch):
        # owa.example.com A-query chases a (type-dependent) CNAME to
        # internal.corp. The resolver answers with IPs whose canonical
        # name is internal.corp; the guard discards the whole answer.
        answer = _FakeAnswer("internal.corp.", ["10.0.0.1"])
        monkeypatch.setattr(dns_mod, "_get_resolver", lambda: _fake_resolver(answer))
        result = await dns_mod._safe_resolve("owa.example.com", "A")
        assert result == [], (
            f"A answer whose canonical name chased to a private suffix must be discarded; got {result!r}"
        )

    @pytest.mark.asyncio
    async def test_public_canonical_chase_is_kept(self, monkeypatch):
        # Legitimate public CNAME delegation (DKIM selector -> provider).
        answer = _FakeAnswer("sel._domainkey.provider.net.", ["v=DKIM1; k=rsa; p=AAA"])
        monkeypatch.setattr(dns_mod, "_get_resolver", lambda: _fake_resolver(answer))
        result = await dns_mod._safe_resolve("sel._domainkey.example.com", "TXT")
        assert result == ["v=DKIM1; k=rsa; p=AAA"]

    @pytest.mark.asyncio
    async def test_no_chase_direct_record_is_kept(self, monkeypatch):
        # canonical == queried name: no CNAME chase, keep the record.
        answer = _FakeAnswer("example.com.", ["v=spf1 -all"])
        monkeypatch.setattr(dns_mod, "_get_resolver", lambda: _fake_resolver(answer))
        result = await dns_mod._safe_resolve("example.com", "TXT")
        assert result == ["v=spf1 -all"]

    @pytest.mark.asyncio
    async def test_cname_query_is_exempt(self, monkeypatch):
        # CNAME queries are exempt: the walker validates targets itself,
        # and a CNAME query returns the immediate record without chasing.
        answer = _FakeAnswer("x.example.com.", ["internal.corp"])
        monkeypatch.setattr(dns_mod, "_get_resolver", lambda: _fake_resolver(answer))
        result = await dns_mod._safe_resolve("x.example.com", "CNAME")
        assert result == ["internal.corp"]

    @pytest.mark.asyncio
    async def test_ptr_query_is_exempt(self, monkeypatch):
        # PTR is exempt: RFC 2317 classless reverse delegation
        # legitimately CNAMEs within the .arpa tree.
        answer = _FakeAnswer("1.0.0.10.in-addr.arpa.", ["host.example.com."])
        monkeypatch.setattr(dns_mod, "_get_resolver", lambda: _fake_resolver(answer))
        result = await dns_mod._safe_resolve("1.0.0.10.in-addr.arpa", "PTR")
        assert result == ["host.example.com"]


class TestResolvesToPublicEndpoint:
    """v1.9.17: ``_resolves_to_public_endpoint`` gives the A-presence
    probes a yes/no resolve signal without leaking. CNAME-first, a
    private CNAME target is rejected before any A/AAAA query fires, and
    the boolean answer never carries the resolved name or address."""

    @pytest.mark.asyncio
    async def test_public_cname_target_is_true(self, monkeypatch):
        plan = {("sso.example.com", "CNAME"): ["edge.okta.com"]}
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        assert await dns_mod._resolves_to_public_endpoint("sso.example.com") is True

    @pytest.mark.asyncio
    async def test_private_cname_target_is_false_without_a_query(self, monkeypatch):
        queries: list[tuple[str, str]] = []

        async def _track(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            queries.append((domain, rdtype))
            return ["internal.corp"] if rdtype == "CNAME" else ["10.0.0.1"]

        monkeypatch.setattr(dns_mod, "_safe_resolve", _track)
        result = await dns_mod._resolves_to_public_endpoint("sso.example.com")
        assert result is False
        assert ("sso.example.com", "A") not in queries, (
            "a private CNAME target must be rejected before any A query fires"
        )

    @pytest.mark.asyncio
    async def test_direct_a_record_is_true(self, monkeypatch):
        plan = {("idp.example.com", "A"): ["203.0.113.10"]}
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve(plan))
        assert await dns_mod._resolves_to_public_endpoint("idp.example.com") is True

    @pytest.mark.asyncio
    async def test_no_records_is_false(self, monkeypatch):
        monkeypatch.setattr(dns_mod, "_safe_resolve", _stub_safe_resolve({}))
        assert await dns_mod._resolves_to_public_endpoint("idp.example.com") is False

    @pytest.mark.asyncio
    async def test_non_public_entry_is_false_without_queries(self, monkeypatch):
        queries: list[tuple[str, str]] = []

        async def _track(domain: str, rdtype: str, **kwargs: Any) -> list[str]:
            queries.append((domain, rdtype))
            return []

        monkeypatch.setattr(dns_mod, "_safe_resolve", _track)
        assert await dns_mod._resolves_to_public_endpoint("host.corp") is False
        assert queries == [], "non-public entry name must be rejected before any query"
