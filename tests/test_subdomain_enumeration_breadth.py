"""v1.9.9 — subdomain enumeration breadth.

The common-prefix wordlist used by the active DNS probe and the
prioritization wordlist used by the CT subdomain sort grew to cover
four classes the prior set missed: data / analytics, AI / ML, internal
operations / tooling, and security. These tests pin the additions so a
future refactor that compacts the wordlist cannot silently drop
coverage.

The additions are intentionally narrow: each prefix maps to a
recognised stack tier with a clear vendor-product mapping (Snowflake
under ``data``, Vertex AI under ``ai``, internal portals under
``internal``, SIEM consoles under ``security``). Speculative additions
not represented here are correctly rejected at PR review.
"""

from __future__ import annotations

from recon_tool.sources.cert_providers import HIGH_SIGNAL_PREFIXES
from recon_tool.sources.dns import _COMMON_SUBDOMAIN_PREFIXES


class TestActiveProbeWordlist:
    """``_detect_common_subdomains`` probes these prefixes directly via
    DNS, so coverage of new stack tiers depends on this tuple."""

    def test_data_tier_prefixes_present(self):
        assert "data" in _COMMON_SUBDOMAIN_PREFIXES
        assert "analytics" in _COMMON_SUBDOMAIN_PREFIXES

    def test_ai_ml_tier_prefixes_present(self):
        assert "ai" in _COMMON_SUBDOMAIN_PREFIXES
        assert "ml" in _COMMON_SUBDOMAIN_PREFIXES

    def test_ops_tier_prefixes_present(self):
        assert "internal" in _COMMON_SUBDOMAIN_PREFIXES
        assert "ops" in _COMMON_SUBDOMAIN_PREFIXES
        assert "tools" in _COMMON_SUBDOMAIN_PREFIXES

    def test_security_tier_prefix_present(self):
        assert "security" in _COMMON_SUBDOMAIN_PREFIXES

    def test_no_duplicate_prefixes(self):
        """A duplicate entry would waste a probe call and hint at a
        merge mistake. The tuple should round-trip through ``set()``
        without losing entries."""
        assert len(_COMMON_SUBDOMAIN_PREFIXES) == len(set(_COMMON_SUBDOMAIN_PREFIXES))


class TestCertProvidersHighSignalParity:
    """The CT subdomain filter uses ``HIGH_SIGNAL_PREFIXES`` to push
    interesting names to the top of the bounded output. The new
    tiers must appear there too; otherwise a CT response that
    surfaces ``data.contoso.com`` could fall off the cap while
    lower-signal entries make it in."""

    def test_data_and_analytics_in_high_signal(self):
        assert "data" in HIGH_SIGNAL_PREFIXES
        assert "analytics" in HIGH_SIGNAL_PREFIXES

    def test_ai_ml_in_high_signal(self):
        assert "ai" in HIGH_SIGNAL_PREFIXES
        assert "ml" in HIGH_SIGNAL_PREFIXES

    def test_ops_tier_in_high_signal(self):
        assert "internal" in HIGH_SIGNAL_PREFIXES
        assert "ops" in HIGH_SIGNAL_PREFIXES
        assert "tools" in HIGH_SIGNAL_PREFIXES

    def test_security_in_high_signal(self):
        assert "security" in HIGH_SIGNAL_PREFIXES

    def test_no_duplicate_high_signal(self):
        assert len(HIGH_SIGNAL_PREFIXES) == len(set(HIGH_SIGNAL_PREFIXES))
