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

from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

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
_VALID_DOMAINS = ["contoso.com", "northwind.example", "fabrikam.test", "x.io"]
_INVALID_DOMAINS = ["", "../etc/passwd", "nodot"]
_ALL_DOMAINS = _VALID_DOMAINS + _INVALID_DOMAINS

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
        cache_put(domain, info)
        if _is_valid(domain):
            self.model[domain] = info
        # Invalid keys are a no-op write; the model (and disk) stay unchanged.

    @rule(domain=_valid_domain, info=_tenant_infos())
    def put_with_unknown_fields(self, domain: str, info: TenantInfo) -> None:
        # Forward compatibility: a payload written by a *newer* recon carries
        # fields this version does not know. They must be ignored on read.
        import json as _json

        payload = tenant_info_to_dict(info)
        payload["_future_scalar"] = 42
        payload["_future_block"] = {"nested": ["a", "b"], "flag": True}
        self._path_for(domain).write_text(_json.dumps(payload), encoding="utf-8")
        self.model[domain] = info

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
