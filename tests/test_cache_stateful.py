"""Stateful (model-based) tests for the TenantInfo disk cache (Track B, B2).

The existing cache tests (`test_cache_roundtrip`, `test_cache_forward_compat`,
`test_cache_cli`) exercise single operations. This drives *arbitrary sequences*
of cache operations (write, write-with-unknown-future-fields, corrupt, stale,
clear, clear-all) across a small pool of valid and invalid domain keys, and
after every step asserts the on-disk state matches a simple model:

  * load-known      — a domain written with a good payload reads back equal.
  * ignore-unknown  — a payload carrying extra future fields still reads back
                      equal (forward compatibility).
  * skip-malformed  — a corrupt payload reads back as None and never raises.
  * TTL eviction    — a stale entry reads back as None.
  * traversal-safe  — invalid / traversal keys never store and always read None.

Sequence-level bugs (a clear that deletes the wrong key, a corrupt entry that
leaks an exception, a stale check that misfires after a particular interleaving)
are the class a single-shot test cannot reach.

The model is deliberately coarse: ``model[domain]`` holds the TenantInfo that a
``cache_get`` should return, and a domain absent from the model must read back
None. Corrupt, stale, cleared, and invalid keys are all "absent" by that rule.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, tzinfo
from pathlib import Path

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule
from typer.testing import CliRunner, Result

from recon_tool.cache import (
    DEFAULT_TTL,
    cache_clear,
    cache_clear_all,
    cache_dir,
    cache_get,
    cache_put,
    tenant_info_to_dict,
)
from recon_tool.models import ConfidenceLevel, TenantInfo
from recon_tool.validator import validate_domain

# A small fixed pool keeps the interesting interleavings (write then clear the
# same key, corrupt then re-write) frequent. Valid keys are already normalized
# (lowercase, no scheme), so the raw string equals its cache key. The invalid
# keys exercise the traversal / format rejection in `_safe_cache_path`.
_VALID_DOMAINS = ["alpha.invalid", "gamma.example", "beta.test", "x.test"]
_INVALID_DOMAINS = ["", "../etc/passwd", "nodot"]
_ALL_DOMAINS = _VALID_DOMAINS + _INVALID_DOMAINS

_FAILURE_MARKERS = ["identity:user_realm", "dns:mx", "source:oidc_discovery", "crt.sh"]

_valid_domain = st.sampled_from(_VALID_DOMAINS)
_any_domain = st.sampled_from(_ALL_DOMAINS)


def _is_valid(domain: str) -> bool:
    try:
        validate_domain(domain)
    except ValueError:
        return False
    return True


@st.composite
def _tenant_infos(draw: st.DrawFn) -> TenantInfo:
    """A TenantInfo varying the simple round-trip-safe fields; complex nested
    fields stay at their defaults so the equality check is unambiguous."""
    # Surrogate codepoints (Cs) are excluded — they cannot be encoded for the
    # JSON round-trip. Control characters are fine: json escapes and restores
    # them, and the cache layer does no scrubbing of its own.
    text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=0, max_size=16)
    return TenantInfo(
        tenant_id=draw(st.one_of(st.none(), st.uuids().map(str))),
        display_name=draw(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=24)),
        default_domain="example.com",
        queried_domain=draw(_valid_domain),
        confidence=draw(st.sampled_from(list(ConfidenceLevel))),
        services=tuple(draw(st.lists(text, max_size=4))),
        slugs=tuple(draw(st.lists(text, max_size=4))),
        auth_type=draw(st.one_of(st.none(), text)),
    )


class CacheLifecycleMachine(RuleBasedStateMachine):
    """Drive cache operation sequences and reconcile disk against the model."""

    def __init__(self) -> None:
        super().__init__()
        self._tmp = tempfile.mkdtemp(prefix="recon-cache-sm-")
        self._prev_env = os.environ.get("RECON_CONFIG_DIR")
        os.environ["RECON_CONFIG_DIR"] = self._tmp
        # domain -> the TenantInfo a cache_get should return. Absence means
        # cache_get must return None.
        self.model: dict[str, TenantInfo] = {}

    def teardown(self) -> None:
        if self._prev_env is None:
            os.environ.pop("RECON_CONFIG_DIR", None)
        else:
            os.environ["RECON_CONFIG_DIR"] = self._prev_env
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _path_for(self, domain: str):
        d = cache_dir()
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{domain}.json"

    @rule(domain=_any_domain, info=_tenant_infos())
    def put_good(self, domain: str, info: TenantInfo) -> None:
        if _is_valid(domain):
            bound_info = replace(info, queried_domain=domain)
            cache_put(domain, bound_info)
            self.model[domain] = bound_info
        else:
            cache_put(domain, info)
        # Invalid keys are a no-op write; the model (and disk) stay unchanged.

    @rule(domain=_valid_domain, info=_tenant_infos())
    def put_with_unknown_fields(self, domain: str, info: TenantInfo) -> None:
        # Forward compatibility: a payload written by a *newer* recon carries
        # fields this version does not know. They must be ignored on read.
        import json as _json

        bound_info = replace(info, queried_domain=domain)
        payload = tenant_info_to_dict(bound_info)
        payload["_future_scalar"] = 42
        payload["_future_block"] = {"nested": ["a", "b"], "flag": True}
        self._path_for(domain).write_text(_json.dumps(payload), encoding="utf-8")
        self.model[domain] = bound_info

    @rule(domain=_valid_domain, info=_tenant_infos())
    def reject_mismatched_domain_payload(self, domain: str, info: TenantInfo) -> None:
        mismatched_domain = next(candidate for candidate in _VALID_DOMAINS if candidate != domain)

        cache_put(domain, replace(info, queried_domain=mismatched_domain))

        # Rejected writes leave any existing model and disk entry unchanged.

    @rule(domain=_valid_domain, info=_tenant_infos(), marker=st.sampled_from(_FAILURE_MARKERS))
    def put_collection_failure(self, domain: str, info: TenantInfo, marker: str) -> None:
        # A collection that recorded a collector failure persists (a delta
        # baseline) but an ordinary read never admits it (issue #223).
        bound_info = replace(info, queried_domain=domain, degraded_sources=(marker,))
        cache_put(domain, bound_info)
        self.model.pop(domain, None)
        restored = cache_get(domain, admit_incomplete=True)
        assert restored is not None
        assert restored.degraded_sources == (marker,)

    @rule(domain=_valid_domain, info=_tenant_infos())
    def put_recovered_ct_fallback(self, domain: str, info: TenantInfo) -> None:
        # A CT provider marker whose channel another provider recovered is a
        # routine fallback, not a collection failure, so it stays reusable.
        bound_info = replace(info, queried_domain=domain, degraded_sources=("crt.sh",), ct_provider_used="certspotter")
        cache_put(domain, bound_info)
        self.model[domain] = bound_info

    @rule(domain=_valid_domain)
    def corrupt(self, domain: str) -> None:
        self._path_for(domain).write_text("{ this is not valid json ", encoding="utf-8")
        self.model.pop(domain, None)  # a corrupt entry must read back as None

    @rule(domain=_valid_domain)
    def make_stale(self, domain: str) -> None:
        path = self._path_for(domain)
        if path.exists():
            old = path.stat().st_mtime - (2 * DEFAULT_TTL)
            os.utime(path, (old, old))
            self.model.pop(domain, None)  # stale-by-TTL must read back as None

    @rule(domain=_any_domain)
    def clear(self, domain: str) -> None:
        cache_clear(domain)
        self.model.pop(domain, None)

    @rule()
    def clear_all(self) -> None:
        cache_clear_all()
        self.model.clear()

    @invariant()
    def disk_matches_model(self) -> None:
        for domain in _ALL_DOMAINS:
            result = cache_get(domain, ttl=DEFAULT_TTL)
            expected = self.model.get(domain)
            if expected is None:
                assert result is None, f"{domain!r} should be absent but cache_get returned a value"
            else:
                assert result is not None, f"{domain!r} should be cached but cache_get returned None"
                assert result.queried_domain == expected.queried_domain
                assert result.default_domain == expected.default_domain
                assert result.display_name == expected.display_name
                assert result.tenant_id == expected.tenant_id
                assert result.confidence == expected.confidence
                assert result.services == expected.services
                assert result.slugs == expected.slugs
                assert result.auth_type == expected.auth_type


CacheLifecycleMachine.TestCase.settings = settings(
    max_examples=40,
    stateful_step_count=24,
    deadline=None,  # filesystem I/O timing varies; the invariants are what matter
)
TestCacheLifecycleStateful = CacheLifecycleMachine.TestCase


# ── CLI recovery journey (issue #223) ─────────────────────────────────────
#
# An offline, fake-clock sequence through the real CLI lookup path. The
# resolver is replaced by a scripted network whose state the test flips between
# an outage and a recovered vantage; the clock drives both the cache file age
# (``json_limits.time``) and the human reuse line (``collection_status``).

_JOURNEY_DOMAIN = "alpha.invalid"


class _FakeClock:
    """Monotonic test clock anchored at the real start time.

    Anchoring at real time keeps files written by ``cache_put`` (real mtime)
    inside the future-mtime tolerance, while ``advance`` ages them.
    """

    def __init__(self) -> None:
        import time as _time

        self.now = _time.time()

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def iso(self) -> str:
        return datetime.fromtimestamp(self.now, UTC).isoformat()


class _ScriptedNetwork:
    """Resolver stand-in: an outage yields a collection with collector failures."""

    def __init__(self, clock: _FakeClock) -> None:
        self.clock = clock
        self.state = "outage"
        self.calls = 0

    def info(self) -> TenantInfo:
        if self.state == "outage":
            return TenantInfo(
                tenant_id=None,
                display_name=_JOURNEY_DOMAIN,
                default_domain=_JOURNEY_DOMAIN,
                queried_domain=_JOURNEY_DOMAIN,
                confidence=ConfidenceLevel.LOW,
                sources=("dns_records",),
                degraded_sources=("certspotter", "crt.sh", "identity:autodiscover", "identity:user_realm"),
                resolved_at=self.clock.iso(),
            )
        if self.state == "sparse":
            # Observed-empty: no services, low confidence, and no failure.
            return TenantInfo(
                tenant_id=None,
                display_name=_JOURNEY_DOMAIN,
                default_domain=_JOURNEY_DOMAIN,
                queried_domain=_JOURNEY_DOMAIN,
                confidence=ConfidenceLevel.LOW,
                sources=("dns_records",),
                resolved_at=self.clock.iso(),
            )
        return TenantInfo(
            tenant_id=None,
            display_name="Synthetic Alpha",
            default_domain=_JOURNEY_DOMAIN,
            queried_domain=_JOURNEY_DOMAIN,
            confidence=ConfidenceLevel.HIGH,
            sources=("dns_records", "oidc_discovery", "user_realm"),
            # crt.sh failed but CertSpotter recovered the CT channel: routine.
            degraded_sources=("crt.sh",),
            ct_provider_used="certspotter",
            resolved_at=self.clock.iso(),
        )

    async def resolve(self, *_args: object, **_kwargs: object) -> tuple[TenantInfo, list[object]]:
        self.calls += 1
        return self.info(), []


class TestCacheRecoveryJourney:
    """Degraded lookup, network recovery, and reuse through the real CLI."""

    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[_FakeClock, _ScriptedNetwork]:
        from recon_tool.formatter import collection_status

        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        clock = _FakeClock()
        network = _ScriptedNetwork(clock)
        monkeypatch.setattr("recon_tool.json_limits.time", clock)

        class _ClockDatetime(datetime):
            @classmethod
            def now(cls, tz: tzinfo | None = None) -> datetime:
                return datetime.fromtimestamp(clock.now, tz or UTC)

        monkeypatch.setattr(collection_status, "datetime", _ClockDatetime)
        monkeypatch.setattr("recon_tool.resolver.resolve_tenant", network.resolve)
        return clock, network

    @staticmethod
    def _lookup(*flags: str) -> Result:
        from recon_tool.cli import app

        result = CliRunner().invoke(app, [_JOURNEY_DOMAIN, *flags])
        assert result.exit_code == 0, result.output
        return result

    @staticmethod
    def _json(*flags: str) -> dict[str, object]:
        import json as _json

        return _json.loads(TestCacheRecoveryJourney._lookup("--json", *flags).output)

    @staticmethod
    def _show_status() -> str:
        from recon_tool.cache_inspection import inspect_result_cache

        entry = inspect_result_cache(_JOURNEY_DOMAIN).entry
        assert entry is not None
        return entry.status

    def test_degraded_lookup_recovers_after_network_returns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock, network = self._setup(tmp_path, monkeypatch)

        # 1. Outage: the partial result is answered and persisted as a delta
        #    baseline, but inspection and reads agree it is not reusable.
        first = self._json()
        assert first["partial"] is True
        assert network.calls == 1
        assert cache_get(_JOURNEY_DOMAIN) is None
        assert cache_get(_JOURNEY_DOMAIN, admit_incomplete=True) is not None
        assert self._show_status() == "not reusable; previous collection had unavailable sources"

        # 2. Still in the outage a minute later: nothing stale is served; the
        #    lookup collects again.
        clock.advance(60)
        assert self._json()["partial"] is True
        assert network.calls == 2

        # 3. Network recovers. --no-cache bypasses the read and the write: it
        #    collects, answers cleanly, and leaves the stored entry alone.
        clock.advance(600)
        network.state = "clean"
        bypass = self._json("--no-cache")
        assert bypass["partial"] is False
        assert network.calls == 3
        stored = cache_get(_JOURNEY_DOMAIN, admit_incomplete=True)
        assert stored is not None
        assert "identity:user_realm" in stored.degraded_sources

        # 4. The next default lookup does not fall back to the degraded entry:
        #    it collects fresh and caches the clean result.
        recovered = self._json()
        assert recovered["partial"] is False
        assert recovered["confidence"] == "high"
        assert network.calls == 4
        assert self._show_status() == "reusable"

        # 5. Three hours later the clean result is reused, and every human
        #    surface says so in one line. JSON keeps the stable contract.
        clock.advance(3 * 3600)
        reused = self._json()
        assert network.calls == 4
        assert reused["confidence"] == "high"
        assert "cached_at" not in reused
        assert "resolved_at" not in reused
        expected = "Cached result from 3 hours ago. Use --no-cache to collect again."
        assert f"cache_note: {expected}" in self._lookup("--plain").output
        assert f"*{expected}*" in self._lookup("--md").output
        assert expected in " ".join(self._lookup().output.split())
        assert network.calls == 4

        # 6. A failed refresh under --no-cache during a new outage answers the
        #    partial result but does not displace the valid clean entry.
        network.state = "outage"
        assert self._json("--no-cache")["partial"] is True
        assert network.calls == 5
        assert self._json()["partial"] is False
        assert network.calls == 5

        # 7. TTL expiry: the clean entry ages out, the refresh fails, and that
        #    failed refresh is not reused by the following lookup.
        clock.advance(DEFAULT_TTL)
        assert self._show_status() == "expired; next lookup refreshes"
        assert self._json()["partial"] is True
        assert network.calls == 6
        clock.advance(60)
        network.state = "clean"
        assert self._json()["partial"] is False
        assert network.calls == 7

    def test_already_persisted_degraded_entry_recovers_without_clearing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clock, network = self._setup(tmp_path, monkeypatch)
        # An entry written by an earlier release, which stored degraded results
        # as reusable. Read admission alone must recover from it.
        cache_put(_JOURNEY_DOMAIN, network.info())
        network.state = "clean"

        assert self._json()["partial"] is False
        assert network.calls == 1
        assert self._json()["confidence"] == "high"
        assert network.calls == 1

    def test_clean_empty_observation_is_still_reused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        clock, network = self._setup(tmp_path, monkeypatch)
        network.state = "sparse"

        first = self._json()
        assert first["partial"] is False
        assert first["confidence"] == "low"
        assert first["services"] == []
        clock.advance(60)
        second = self._json()

        assert network.calls == 1
        assert second["confidence"] == "low"
        assert self._show_status() == "reusable"

    def test_narrow_scope_lookups_neither_read_nor_write_the_shared_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clock, network = self._setup(tmp_path, monkeypatch)
        network.state = "clean"

        self._json("--no-ct")
        self._json("--direct-probes")

        assert network.calls == 2
        assert cache_get(_JOURNEY_DOMAIN, admit_incomplete=True) is None
