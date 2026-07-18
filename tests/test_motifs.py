"""Unit tests for the v1.7 chain motif library.

Covers:
- YAML loader rejects malformed entries.
- Built-in catalog loads with expected motifs.
- Matcher fires on ordered subsequences and skips on misses.
- Catalog cap and per-marker pattern cap are honored.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from recon_tool.motifs import (
    _MAX_MOTIF_YAML_BYTES,
    MOTIF_CHAIN_HARD_CAP,
    ChainMotif,
    load_motifs,
    match_chain_motifs,
)


@pytest.fixture(autouse=True)
def _clear_motif_cache():
    """Reset the module-level cache so tests aren't order-dependent."""
    import recon_tool.motifs as _m

    _m._cache_state.motifs = None
    yield
    _m._cache_state.motifs = None


class TestBuiltinCatalog:
    def test_loads_nonempty(self):
        motifs = load_motifs()
        assert len(motifs) >= 5  # we ship more than five
        for m in motifs:
            assert isinstance(m, ChainMotif)

    def test_cloudflare_to_aws_present(self):
        motifs = load_motifs()
        names = {m.name for m in motifs}
        assert "cloudflare_to_aws" in names

    def test_microsoft_triad_motif_present_and_fires(self):
        motifs = load_motifs()
        chain = [
            "alpha.trafficmanager.net",
            "alpha.azurefd.net",
            "alpha.t-msedge.net",
        ]

        matches = match_chain_motifs(chain, motifs, subdomain="api.alpha.invalid")

        assert any(m.motif_name == "tm_to_azurefd_to_msedge" for m in matches)
        triad = next(m for m in matches if m.motif_name == "tm_to_azurefd_to_msedge")
        assert triad.subdomain == "api.alpha.invalid"
        assert triad.chain == tuple(chain)

    def test_microsoft_triad_motif_requires_order(self):
        motifs = load_motifs()
        chain = [
            "alpha.azurefd.net",
            "alpha.trafficmanager.net",
            "alpha.t-msedge.net",
        ]

        matches = match_chain_motifs(chain, motifs, subdomain="api.alpha.invalid")

        assert all(m.motif_name != "tm_to_azurefd_to_msedge" for m in matches)

    def test_no_motif_chain_exceeds_cap(self):
        for m in load_motifs():
            assert len(m.markers) <= MOTIF_CHAIN_HARD_CAP


class TestMatchSemantics:
    """Matcher walks the chain in order; markers must appear in sequence."""

    def _motif(self, name: str, markers_spec: list[tuple[str, list[str]]]) -> ChainMotif:
        from recon_tool.motifs import _MotifMarker

        return ChainMotif(
            name=name,
            display_name=name,
            description="",
            confidence="medium",
            markers=tuple(_MotifMarker(name=mn, patterns=tuple(ps)) for mn, ps in markers_spec),
        )

    def test_two_marker_motif_fires_in_order(self):
        motif = self._motif(
            "cf_to_aws",
            [("cf", ["cloudflare.net"]), ("aws", ["amazonaws.com"])],
        )
        chain = ["foo.cloudflare.net", "bar.amazonaws.com"]
        matches = match_chain_motifs(chain, (motif,), subdomain="api.example.com")
        assert len(matches) == 1
        assert matches[0].chain == ("foo.cloudflare.net", "bar.amazonaws.com")
        assert matches[0].subdomain == "api.example.com"

    def test_reverse_order_does_not_fire(self):
        """Markers are positional: AWS-then-Cloudflare is a different shape."""
        motif = self._motif(
            "cf_to_aws",
            [("cf", ["cloudflare.net"]), ("aws", ["amazonaws.com"])],
        )
        chain = ["foo.amazonaws.com", "bar.cloudflare.net"]
        assert match_chain_motifs(chain, (motif,)) == []

    def test_intermediate_hops_allowed(self):
        """A passive proxy chain may have hops between matched markers."""
        motif = self._motif(
            "cf_to_aws",
            [("cf", ["cloudflare.net"]), ("aws", ["amazonaws.com"])],
        )
        chain = ["foo.cloudflare.net", "middle.example.com", "bar.amazonaws.com"]
        matches = match_chain_motifs(chain, (motif,))
        assert len(matches) == 1
        assert matches[0].chain == ("foo.cloudflare.net", "bar.amazonaws.com")

    def test_missing_first_marker_skips(self):
        motif = self._motif(
            "cf_to_aws",
            [("cf", ["cloudflare.net"]), ("aws", ["amazonaws.com"])],
        )
        assert match_chain_motifs(["bar.amazonaws.com"], (motif,)) == []

    def test_missing_second_marker_skips(self):
        motif = self._motif(
            "cf_to_aws",
            [("cf", ["cloudflare.net"]), ("aws", ["amazonaws.com"])],
        )
        assert match_chain_motifs(["foo.cloudflare.net"], (motif,)) == []

    def test_empty_chain_returns_empty(self):
        motif = self._motif("dummy", [("a", ["x"])])
        assert match_chain_motifs([], (motif,)) == []

    def test_empty_catalog_returns_empty(self):
        assert match_chain_motifs(["x.cloudflare.net"], ()) == []

    def test_real_catalog_fires_on_real_chain(self):
        """Sanity: the shipped catalog fires on a realistic CDN-to-origin chain."""
        motifs = load_motifs()
        chain = ["edge.cloudflare.net", "origin.amazonaws.com"]
        matches = match_chain_motifs(chain, motifs)
        assert any(m.motif_name == "cloudflare_to_aws" for m in matches)


class TestUserConfigAdditive:
    """User motifs from ~/.recon/motifs.yaml are additive, can't override built-ins."""

    def test_user_path_default_does_not_break(self):
        # The default user path may not exist; loader must tolerate that.
        motifs = load_motifs(reload=True)
        assert len(motifs) > 0  # built-ins still loaded

    def test_oversized_user_yaml_is_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        payload = (
            "motifs:\n"
            "  - name: oversized\n"
            "    display_name: oversized\n"
            "    confidence: medium\n"
            "    description: "
            + "x" * _MAX_MOTIF_YAML_BYTES
            + "\n    chain: [{name: a, match: [example.com]}]\n"
        )
        (tmp_path / "motifs.yaml").write_text(payload, encoding="utf-8")

        motifs = load_motifs(reload=True)
        names = {m.name for m in motifs}
        assert "oversized" not in names
        assert "cloudflare_to_aws" in names

    def test_recursive_yaml_parse_failure_is_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        import recon_tool.motifs as motifs_mod

        original_safe_load = motifs_mod.yaml.safe_load

        def _safe_load(text: str):
            if "raise-recursion" in text:
                raise RecursionError("too deep")
            return original_safe_load(text)

        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        monkeypatch.setattr(motifs_mod.yaml, "safe_load", _safe_load)
        (tmp_path / "motifs.yaml").write_text("raise-recursion\n", encoding="utf-8")

        motifs = load_motifs(reload=True)
        assert {m.name for m in motifs}


class TestValidatorRejects:
    def test_rejects_missing_name(self, tmp_path: Path):
        from recon_tool.motifs import _load_from_path

        path = tmp_path / "bad.yaml"
        path.write_text(
            "motifs:\n  - display_name: 'no name'\n    confidence: medium\n    chain: [{name: a, match: [x]}]\n"
        )
        assert _load_from_path(path) == []

    def test_rejects_invalid_confidence(self, tmp_path: Path):
        from recon_tool.motifs import _load_from_path

        path = tmp_path / "bad.yaml"
        path.write_text(
            "motifs:\n  - name: bad\n    display_name: bad\n    confidence: certain\n"
            "    chain: [{name: a, match: [x]}]\n"
        )
        assert _load_from_path(path) == []

    def test_rejects_chain_too_long(self, tmp_path: Path):
        from recon_tool.motifs import _load_from_path

        markers = "\n".join(f"      - {{name: m{i}, match: [x{i}]}}" for i in range(MOTIF_CHAIN_HARD_CAP + 1))
        path = tmp_path / "bad.yaml"
        path.write_text(
            f"motifs:\n  - name: too_long\n    display_name: too long\n    confidence: medium\n    chain:\n{markers}\n"
        )
        assert _load_from_path(path) == []
