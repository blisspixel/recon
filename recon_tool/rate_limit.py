"""Adaptive rate limiter + circuit breaker for outbound HTTP.

Used today by the CT providers (`crt.sh` and CertSpotter). Both
providers publish per-IP rate limits, but the limits are opaque under
load (crt.sh has tightened from 60/min to 5/min under abuse, and may
tighten further; CertSpotter's free tier subdomain quota is 10/day
but server behavior on overload is unspecified). A fixed token-bucket
rate would be either too conservative (wasted budget on a healthy
provider) or too aggressive (causes server-side 429 storms that the
local pacer cannot prevent).

Design: AIMD pacing + circuit breaker per provider.

- **AIMD**: start at a conservative interval. On every successful
  acquire-and-use cycle, additive-decrease the interval (gradually
  faster). On every 429 from the server, multiplicative-increase
  the interval (immediately slower). Bounded between ``min_interval``
  and ``max_interval``.

- **Circuit breaker**: track consecutive failures. After
  ``failure_threshold`` failures in a row, open the circuit for
  ``cooldown_s`` seconds. While open, ``acquire()`` raises
  ``RateLimited`` immediately rather than waiting on the rate.
  After the cooldown, a single probe is allowed (half-open); on
  success the breaker closes; on failure the cooldown doubles
  (bounded by ``max_cooldown_s``).

- **Retry-After**: when a caller observes a 429 with a ``Retry-After``
  header, it passes the value to ``on_rate_limited(retry_after=N)``.
  The limiter then uses ``max(current_interval, retry_after)`` as
  the new interval and trips the breaker if appropriate.

- **Bounded wait**: ``acquire()`` waits at most ``max_wait_s`` for
  a slot. If the limiter is saturated, it raises ``RateLimited``
  and the orchestrator marks the provider degraded. This keeps a
  corpus-scale run from blocking forever on a saturated provider.

Zero API keys. The defaults below are conservative against the
published free-tier limits so an operator on a fresh IP gets sane
behavior with no configuration.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger("recon")

__all__ = [
    "AdaptiveRateLimiter",
    "RateLimited",
    "ct_rate_limiter_certspotter",
    "ct_rate_limiter_crtsh",
    "rate_limit_state_dir",
]


def rate_limit_state_dir() -> Path:
    """Directory holding persisted limiter state. Sibling of the CT cache.

    Override via ``RECON_CONFIG_DIR`` for tests / non-default homes;
    matches the convention used by ``recon_tool.ct_cache.ct_cache_dir``.
    """
    base = os.environ.get("RECON_CONFIG_DIR")
    root = Path(base) if base else Path.home() / ".recon"
    return root / "rate-limit-state"


# Maximum age for a persisted snapshot. Older state is ignored on
# load: a 24-hour-old breaker reading is almost always stale (server-
# side limits reset on different schedules, and an operator returning
# the next day should not inherit yesterday's punishment indefinitely).
_PERSIST_MAX_AGE_SECONDS = 24 * 3600

# How often (in seconds) the limiter snapshots its state to disk while
# running. Persistence after every state change is wasteful for an
# interactive single-domain lookup; this floor keeps writes bounded
# while still capturing breaker trips and material interval shifts.
_PERSIST_WRITE_INTERVAL_S = 5.0


class RateLimited(Exception):
    """Raised when ``AdaptiveRateLimiter.acquire`` cannot grant a slot."""


class AdaptiveRateLimiter:
    """Per-provider AIMD pacing + circuit breaker.

    State lives in this object and is per-process, per-loop. Each
    provider gets its own instance via the factories below; callers
    do not construct these directly outside of tests.
    """

    def __init__(
        self,
        name: str,
        min_interval_s: float,
        max_interval_s: float,
        start_interval_s: float | None = None,
        max_wait_s: float = 120.0,
        success_decrease: float = 0.9,
        failure_increase_factor: float = 2.0,
        failure_threshold: int = 3,
        cooldown_s: float = 60.0,
        max_cooldown_s: float = 600.0,
        persist: bool = True,
    ) -> None:
        if not (0.0 < min_interval_s <= max_interval_s):
            msg = f"invalid interval bounds for {name}"
            raise ValueError(msg)
        self.name = name
        self.min_interval_s = min_interval_s
        self.max_interval_s = max_interval_s
        self._interval_s: float = start_interval_s if start_interval_s is not None else min_interval_s
        self._max_wait_s = max_wait_s
        self._success_decrease = success_decrease
        self._failure_increase_factor = failure_increase_factor
        self._failure_threshold = failure_threshold
        self._cooldown_s = cooldown_s
        self._max_cooldown_s = max_cooldown_s
        # Tally fields used for end-of-run summaries. Bumped by callers
        # via on_success / on_rate_limited / on_other_failure.
        self._success_count: int = 0
        self._rate_limit_count: int = 0
        self._other_failure_count: int = 0
        self._breaker_trip_count: int = 0
        self._local_decline_count: int = 0  # acquire() raised RateLimited

        self._next_slot_at: float = time.monotonic()
        self._consecutive_failures: int = 0
        self._breaker_open_until: float = 0.0
        self._current_cooldown_s: float = cooldown_s
        self._lock = asyncio.Lock()

        self._persist = persist
        self._last_persist_at: float = 0.0
        if persist:
            self._load_persisted()

    def _breaker_state(self) -> tuple[bool, float]:
        """Return (is_open, seconds_until_close). Closed means (False, 0.0)."""
        now = time.monotonic()
        if now >= self._breaker_open_until:
            return False, 0.0
        return True, self._breaker_open_until - now

    # ── Persistence ───────────────────────────────────────────────────────

    def _state_path(self) -> Path:
        return rate_limit_state_dir() / f"{self.name}.json"

    def _load_persisted(self) -> None:
        """Inherit breaker / interval state from a prior process if fresh.

        Stored on disk as wall-clock ISO timestamps so a restart on a
        different boot (monotonic clock resets) still reads correctly.
        Stale entries (> _PERSIST_MAX_AGE_SECONDS) are ignored: a 24-
        hour-old reading is almost always wrong, and we would rather
        re-probe than inherit a stale punishment.

        Failures (missing file, corrupt JSON, schema mismatch) silently
        fall back to fresh defaults. The limiter must work without
        persistence; this is opportunistic warm-start, not load-bearing.
        """
        path = self._state_path()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, FileNotFoundError):
            return
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return
        if not isinstance(data, dict):
            return
        saved_at_iso = data.get("saved_at")
        if not isinstance(saved_at_iso, str):
            return
        try:
            saved_at = datetime.fromisoformat(saved_at_iso.replace("Z", "+00:00"))
        except ValueError:
            return
        age_s = (datetime.now(UTC) - saved_at).total_seconds()
        if age_s < 0 or age_s > _PERSIST_MAX_AGE_SECONDS:
            return
        # Floats; clamp to documented bounds in case the on-disk file
        # was hand-edited or written by a future schema.
        try:
            interval = float(data.get("interval_s", self._interval_s))
            cooldown = float(data.get("current_cooldown_s", self._cooldown_s))
            cons_fail = int(data.get("consecutive_failures", 0))
            breaker_remaining_s = float(data.get("breaker_remaining_s", 0.0))
        except (TypeError, ValueError):
            return
        self._interval_s = max(self.min_interval_s, min(self.max_interval_s, interval))
        self._current_cooldown_s = max(self._cooldown_s, min(self._max_cooldown_s, cooldown))
        self._consecutive_failures = max(0, cons_fail)
        # Convert the persisted remaining-cooldown into a monotonic deadline.
        # Subtract the wall-clock age so an operator restarting after the
        # persisted breaker would have closed sees a closed breaker.
        effective_remaining = max(0.0, breaker_remaining_s - age_s)
        if effective_remaining > 0:
            self._breaker_open_until = time.monotonic() + effective_remaining
        logger.debug(
            "%s: loaded persisted state (age=%.1fs interval=%.1fs failures=%d breaker_remaining=%.1fs)",
            self.name,
            age_s,
            self._interval_s,
            self._consecutive_failures,
            effective_remaining,
        )

    def _persist_state(self, *, force: bool = False) -> None:
        """Snapshot current state to disk.

        Rate-limited to one write per ``_PERSIST_WRITE_INTERVAL_S`` so
        a tight burst of events does not thrash the filesystem.
        Failures (no write permission, disk full) are swallowed: the
        limiter still works without persistence.
        """
        if not self._persist:
            return
        now = time.monotonic()
        if not force and (now - self._last_persist_at) < _PERSIST_WRITE_INTERVAL_S:
            return
        self._last_persist_at = now
        is_open, remaining = self._breaker_state()
        payload = {
            "name": self.name,
            "saved_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "interval_s": round(self._interval_s, 3),
            "current_cooldown_s": round(self._current_cooldown_s, 3),
            "consecutive_failures": self._consecutive_failures,
            "breaker_open": is_open,
            "breaker_remaining_s": round(remaining, 3) if is_open else 0.0,
            "success_count": self._success_count,
            "rate_limit_count": self._rate_limit_count,
            "other_failure_count": self._other_failure_count,
            "breaker_trip_count": self._breaker_trip_count,
            "local_decline_count": self._local_decline_count,
        }
        try:
            path = self._state_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            logger.debug("%s: failed to persist state: %s", self.name, exc)

    async def acquire(self) -> None:
        """Wait for a slot. Raise ``RateLimited`` on timeout or open breaker."""
        async with self._lock:
            # Breaker check first. An open breaker fails fast so the
            # orchestrator can fall through to the next provider /
            # cache without burning wall-clock on a known-dead path.
            is_open, remaining = self._breaker_state()
            if is_open:
                self._local_decline_count += 1
                msg = (
                    f"{self.name}: circuit breaker open for {remaining:.0f}s more "
                    f"(consecutive_failures={self._consecutive_failures})"
                )
                raise RateLimited(msg)

            now = time.monotonic()
            wait = max(0.0, self._next_slot_at - now)
            if wait > self._max_wait_s:
                self._local_decline_count += 1
                msg = (
                    f"{self.name}: next slot in {wait:.0f}s exceeds max wait "
                    f"{self._max_wait_s:.0f}s (current interval {self._interval_s:.1f}s)"
                )
                raise RateLimited(msg)
            if wait > 0.0:
                await asyncio.sleep(wait)
            # Issue the slot by stamping the next-available time.
            self._next_slot_at = max(self._next_slot_at, time.monotonic()) + self._interval_s

    def on_success(self) -> None:
        """Caller observed a successful provider response. Speed up gently."""
        self._success_count += 1
        self._consecutive_failures = 0
        # Reset breaker cooldown on any success so a half-open probe
        # that succeeds returns the breaker to a healthy baseline.
        self._current_cooldown_s = self._cooldown_s
        self._breaker_open_until = 0.0
        # Multiplicative decrease toward min_interval. With factor 0.9
        # the interval halves over roughly seven successive successes,
        # which is gradual enough not to immediately re-trip the
        # provider's rate limit.
        new = self._interval_s * self._success_decrease
        self._interval_s = max(self.min_interval_s, new)
        self._persist_state()

    def on_rate_limited(self, retry_after_s: float | None = None) -> None:
        """Caller observed a 429. Slow down hard, trip the breaker if needed."""
        self._rate_limit_count += 1
        self._consecutive_failures += 1
        # Multiplicative-increase. If the server tells us how long to
        # wait via Retry-After, treat that as a hard floor.
        new = self._interval_s * self._failure_increase_factor
        if retry_after_s is not None and retry_after_s > 0.0:
            new = max(new, retry_after_s)
        self._interval_s = min(self.max_interval_s, new)
        # Push the next-available time so the next caller waits the
        # new interval, not the old one.
        self._next_slot_at = max(self._next_slot_at, time.monotonic() + self._interval_s)
        # Trip the breaker if we've crossed the threshold.
        if self._consecutive_failures >= self._failure_threshold:
            self._breaker_open_until = time.monotonic() + self._current_cooldown_s
            self._breaker_trip_count += 1
            logger.debug(
                "%s: breaker opened for %.0fs after %d consecutive failures",
                self.name,
                self._current_cooldown_s,
                self._consecutive_failures,
            )
            # Exponential backoff on the breaker itself so a flaky
            # provider does not keep flapping at the same cadence.
            self._current_cooldown_s = min(self._max_cooldown_s, self._current_cooldown_s * 2.0)
        self._persist_state(force=True)

    def on_other_failure(self) -> None:
        """Caller observed a non-429 failure (timeout, 5xx). Counts toward
        the breaker but does not bump the interval; transient errors should
        not push a healthy provider into a slow mode."""
        self._other_failure_count += 1
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._failure_threshold:
            self._breaker_open_until = time.monotonic() + self._current_cooldown_s
            self._breaker_trip_count += 1
            self._current_cooldown_s = min(self._max_cooldown_s, self._current_cooldown_s * 2.0)
            self._persist_state(force=True)
        else:
            self._persist_state()

    def snapshot(self) -> dict[str, object]:
        """Return current state for logging / panel surfacing."""
        is_open, remaining = self._breaker_state()
        return {
            "name": self.name,
            "interval_s": round(self._interval_s, 2),
            "next_slot_in_s": round(max(0.0, self._next_slot_at - time.monotonic()), 2),
            "consecutive_failures": self._consecutive_failures,
            "breaker_open": is_open,
            "breaker_remaining_s": round(remaining, 2),
            "success_count": self._success_count,
            "rate_limit_count": self._rate_limit_count,
            "other_failure_count": self._other_failure_count,
            "breaker_trip_count": self._breaker_trip_count,
            "local_decline_count": self._local_decline_count,
        }


# Process-wide singletons, lazily allocated per running loop. Two
# distinct loops (e.g. a test that spawns its own loop) get their own
# limiter so state is not leaked across loop teardowns.
_limiters_by_loop: dict[int, dict[str, AdaptiveRateLimiter]] = {}


def _get_limiter(name: str, **kwargs: object) -> AdaptiveRateLimiter:
    loop = asyncio.get_running_loop()
    key = id(loop)
    table = _limiters_by_loop.get(key)
    if table is None:
        table = {}
        _limiters_by_loop[key] = table
    limiter = table.get(name)
    if limiter is None:
        limiter = AdaptiveRateLimiter(name, **kwargs)  # type: ignore[arg-type]
        table[name] = limiter
    return limiter


def ct_rate_limiter_crtsh() -> AdaptiveRateLimiter:
    """crt.sh adaptive limiter.

    Starts at 15s/request (4/min, under the documented 5/min per-IP
    limit). Backs off multiplicatively on 429, capped at 5 minutes
    between requests. Circuit breaker opens after 3 consecutive
    failures for an initial 60s cooldown, doubling each subsequent
    trip up to 10 minutes.
    """
    return _get_limiter(
        "crt.sh",
        min_interval_s=10.0,
        max_interval_s=300.0,
        start_interval_s=15.0,
        max_wait_s=60.0,
        failure_threshold=3,
        cooldown_s=60.0,
    )


def ct_rate_limiter_certspotter() -> AdaptiveRateLimiter:
    """CertSpotter adaptive limiter.

    Starts at 30s/request. CertSpotter's free-tier subdomain quota is
    10/day, so a corpus run on a fresh IP burns the daily budget in
    five minutes regardless of pacing. The breaker is what actually
    saves the run: after the first 429 the interval jumps to 60s;
    after three in a row the breaker opens for 60s, then 120s, then
    240s, capped at 10 minutes. Long corpus runs effectively idle
    CertSpotter once the daily quota is exhausted, letting crt.sh
    and the on-disk cache carry the load.
    """
    return _get_limiter(
        "certspotter",
        min_interval_s=20.0,
        max_interval_s=300.0,
        start_interval_s=30.0,
        max_wait_s=120.0,
        failure_threshold=3,
        cooldown_s=60.0,
    )
