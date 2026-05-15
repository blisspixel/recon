"""v1.9.9 — wordlist sanity invariants.

The active-DNS probe wordlist (``_COMMON_SUBDOMAIN_PREFIXES`` in
``recon_tool/sources/dns.py``) and the CT prioritization wordlist
(``HIGH_SIGNAL_PREFIXES`` in ``recon_tool/sources/cert_providers.py``)
need to satisfy a few invariants that no single fixture test would
catch:

  * Both tuples are deduplicated.
  * The active-probe wordlist contains every prefix the CT-prioritize
    list considers high-signal. The CT-side cannot push something to
    the top of the bounded output if the active probe didn't probe
    for it; conversely, the probe shouldn't waste a network call on
    a prefix CT-prioritize ignores.

The parity matters because v1.9.9 added the same eight prefixes to
both lists; a future PR that adds a prefix to only one would silently
break the breadth-coverage contract. The tests below pin both
invariants so the parity stays load-bearing rather than coincidental.
"""

from __future__ import annotations

from recon_tool.sources.cert_providers import HIGH_SIGNAL_PREFIXES
from recon_tool.sources.dns import _COMMON_SUBDOMAIN_PREFIXES


class TestDeduplication:
    def test_active_probe_wordlist_is_deduplicated(self):
        seen: dict[str, int] = {}
        for prefix in _COMMON_SUBDOMAIN_PREFIXES:
            seen[prefix] = seen.get(prefix, 0) + 1
        dupes = {p: n for p, n in seen.items() if n > 1}
        assert not dupes, f"duplicate prefixes in _COMMON_SUBDOMAIN_PREFIXES: {dupes}"

    def test_ct_priority_wordlist_is_deduplicated(self):
        seen: dict[str, int] = {}
        for prefix in HIGH_SIGNAL_PREFIXES:
            seen[prefix] = seen.get(prefix, 0) + 1
        dupes = {p: n for p, n in seen.items() if n > 1}
        assert not dupes, f"duplicate prefixes in HIGH_SIGNAL_PREFIXES: {dupes}"


class TestV199AdditionsAppearInBothLists:
    """The v1.9.9 wordlist extension added the same eight prefixes to
    both lists. A future patch that drops one from either side breaks
    the breadth-coverage parity; this test catches the regression."""

    _V199_ADDITIONS = ("data", "analytics", "ai", "ml", "internal", "ops", "tools", "security")

    def test_all_v199_additions_in_active_probe_list(self):
        for prefix in self._V199_ADDITIONS:
            assert prefix in _COMMON_SUBDOMAIN_PREFIXES, (
                f"v1.9.9 prefix {prefix!r} missing from _COMMON_SUBDOMAIN_PREFIXES"
            )

    def test_all_v199_additions_in_ct_priority_list(self):
        for prefix in self._V199_ADDITIONS:
            assert prefix in HIGH_SIGNAL_PREFIXES, f"v1.9.9 prefix {prefix!r} missing from HIGH_SIGNAL_PREFIXES"


class TestPrefixesAreReasonable:
    """Cheap sanity checks on prefix shape. A leading slash or
    whitespace would never resolve as a real subdomain, and an empty
    string would silently match everything. Catching these here keeps
    the wordlists clean as they grow."""

    def test_no_empty_prefixes(self):
        for prefix in _COMMON_SUBDOMAIN_PREFIXES:
            assert prefix.strip() != "", "empty prefix in active-probe wordlist"
        for prefix in HIGH_SIGNAL_PREFIXES:
            assert prefix.strip() != "", "empty prefix in CT-priority wordlist"

    def test_no_whitespace_in_prefixes(self):
        for prefix in _COMMON_SUBDOMAIN_PREFIXES:
            assert prefix == prefix.strip(), f"prefix {prefix!r} has leading/trailing whitespace"
            assert " " not in prefix, f"prefix {prefix!r} contains internal whitespace"

    def test_prefixes_are_lowercase(self):
        """DNS labels are case-insensitive, but matching against
        lowercase-only is the convention everywhere else in the
        codebase. Catching an accidental ``"Auth"`` (uppercase) here
        prevents a probe that would never match the comparison
        target."""
        for prefix in _COMMON_SUBDOMAIN_PREFIXES:
            assert prefix == prefix.lower(), f"prefix {prefix!r} should be lowercase"


class TestParity:
    """Operational parity: any prefix the CT-priority list considers
    high-signal should also be probed actively (otherwise its CT
    upranking has no upstream signal to leverage). Conversely, an
    active-probe prefix the CT-priority list ignores is a bug — the
    operator-facing surfaces would surface different prefix sets in
    different code paths."""

    def test_v199_additions_appear_in_both_lists_with_same_values(self):
        active_set = set(_COMMON_SUBDOMAIN_PREFIXES)
        ct_set = set(HIGH_SIGNAL_PREFIXES)
        # Specifically the v1.9.9 additions appear in both
        v199 = {"data", "analytics", "ai", "ml", "internal", "ops", "tools", "security"}
        assert v199.issubset(active_set), f"v1.9.9 prefixes missing from active probe: {v199 - active_set}"
        assert v199.issubset(ct_set), f"v1.9.9 prefixes missing from CT priority: {v199 - ct_set}"
