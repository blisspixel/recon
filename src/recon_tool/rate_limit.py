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
import contextlib
import json
import logging
import math
import os
import re
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from recon_tool.json_limits import load_bounded_json_file

logger = logging.getLogger("recon")

__all__ = [
    "AdaptiveRateLimiter",
    "RateLimited",
    "ct_rate_limiter_certspotter",
    "ct_rate_limiter_crtsh",
    "rate_limit_state_dir",
]


def rate_limit_state_dir() -> Path:
    """Directory holding persisted limiter state.

    RECON_CONFIG_DIR / legacy ~/.recon / XDG state dir, via recon_tool.paths.
    """
    from recon_tool.paths import state_dir

    return state_dir() / "rate-limit-state"


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
_MAX_PERSISTED_STATE_BYTES = 64 * 1024
_PERSISTED_STATE_VERSION = 1
_MAX_PERSISTED_FAILURES = 1_000_000
_LIMITER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _finite_state_number(data: dict[object, object], field: str) -> float:
    raw = data.get(field)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError(f"{field} must be numeric")
    try:
        value = float(raw)
    except OverflowError as exc:
        raise ValueError(f"{field} exceeds the supported numeric range") from exc
    if not math.isfinite(value):
        raise ValueError(f"{field} must be finite")
    return value


def _bounded_state_count(data: dict[object, object], field: str) -> int:
    raw = data.get(field)
    if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= _MAX_PERSISTED_FAILURES:
        raise ValueError(f"{field} must be a bounded non-negative integer")
    return raw


def _is_positive_integer(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 1


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
        if _LIMITER_NAME_RE.fullmatch(name) is None:
            raise ValueError("rate limiter name must be a bounded filesystem-safe identifier")
        if not (
            math.isfinite(min_interval_s) and math.isfinite(max_interval_s) and 0.0 < min_interval_s <= max_interval_s
        ):
            msg = f"invalid interval bounds for {name}"
            raise ValueError(msg)
        if start_interval_s is not None and (
            not math.isfinite(start_interval_s) or not min_interval_s <= start_interval_s <= max_interval_s
        ):
            raise ValueError(f"invalid starting interval for {name}")
        if not math.isfinite(max_wait_s) or max_wait_s < 0.0:
            raise ValueError(f"invalid maximum wait for {name}")
        if not math.isfinite(success_decrease) or not 0.0 < success_decrease <= 1.0:
            raise ValueError(f"invalid success decrease factor for {name}")
        if not math.isfinite(failure_increase_factor) or failure_increase_factor < 1.0:
            raise ValueError(f"invalid failure increase factor for {name}")
        if not _is_positive_integer(failure_threshold):
            raise ValueError(f"invalid failure threshold for {name}")
        if (
            not math.isfinite(cooldown_s)
            or not math.isfinite(max_cooldown_s)
            or cooldown_s <= 0.0
            or max_cooldown_s < cooldown_s
        ):
            raise ValueError(f"invalid cooldown bounds for {name}")
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
            data, _file_stat, _age_seconds = load_bounded_json_file(path, maximum_bytes=_MAX_PERSISTED_STATE_BYTES)
        except (ValueError, TypeError, RecursionError):
            return
        except OSError:
            return
        if not isinstance(data, dict):
            return
        if data.get("_state_version") != _PERSISTED_STATE_VERSION or data.get("name") != self.name:
            return
        saved_at_iso = data.get("saved_at")
        if not isinstance(saved_at_iso, str):
            return
        try:
            saved_at = datetime.fromisoformat(saved_at_iso.replace("Z", "+00:00"))
        except ValueError:
            return
        if saved_at.tzinfo is None or saved_at.utcoffset() is None:
            return
        age_s = (datetime.now(UTC) - saved_at).total_seconds()
        if not math.isfinite(age_s) or age_s < 0 or age_s > _PERSIST_MAX_AGE_SECONDS:
            return
        try:
            interval = _finite_state_number(data, "interval_s")
            cooldown = _finite_state_number(data, "current_cooldown_s")
            breaker_remaining_s = _finite_state_number(data, "breaker_remaining_s")
            cons_fail = _bounded_state_count(data, "consecutive_failures")
        except ValueError:
            return
        if not (
            self.min_interval_s <= interval <= self.max_interval_s
            and self._cooldown_s <= cooldown <= self._max_cooldown_s
            and 0.0 <= breaker_remaining_s <= self._max_cooldown_s
        ):
            return
        self._interval_s = interval
        self._current_cooldown_s = cooldown
        self._consecutive_failures = cons_fail
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
            "_state_version": _PERSISTED_STATE_VERSION,
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
            directory = path.parent.resolve()
            path = directory / path.name
            descriptor, temporary_name = tempfile.mkstemp(dir=str(directory), prefix=f"{path.stem}.", suffix=".tmp")
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(payload, indent=2))
                os.replace(temporary_name, path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(temporary_name)
                raise
        except (OSError, TypeError, ValueError) as exc:
            logger.debug("%s: failed to persist state: %s", self.name, exc)

    async def acquire(self) -> None:
        """Wait for a slot. Raise ``RateLimited`` on timeout or open breaker."""
        deadline = time.monotonic() + self._max_wait_s
        first_attempt = True
        while True:
            async with self._lock:
                wait = self._reserve_or_delay(deadline, first_attempt=first_attempt)
            if wait is None:
                return
            first_attempt = False
            # Never hold the reservation lock while sleeping. A later caller
            # must be able to observe newly opened breaker state immediately.
            await asyncio.sleep(wait)

    def _reserve_or_delay(self, deadline: float, *, first_attempt: bool) -> float | None:
        """Reserve an available slot or return the bounded delay before retry."""
        # Feedback callbacks are synchronous and can move the slot or open the
        # breaker while another acquire sleeps. Every lock acquisition rechecks
        # both invariants before issuing work.
        is_open, remaining = self._breaker_state()
        if is_open:
            msg = (
                f"{self.name}: circuit breaker open for {remaining:.0f}s more "
                f"(consecutive_failures={self._consecutive_failures})"
            )
            raise self._decline(msg)

        now = time.monotonic()
        wait = max(0.0, self._next_slot_at - now)
        remaining_budget = max(0.0, deadline - now)
        if wait <= 0.0 and (first_attempt or remaining_budget > 0.0):
            self._next_slot_at = now + self._interval_s
            return None

        # Equality cannot complete within the stated maximum: the coroutine
        # must still resume and reacquire the lock. Reject it deterministically
        # instead of racing an equal-deadline timeout.
        if wait >= remaining_budget:
            msg = (
                f"{self.name}: next slot in {wait:.0f}s does not fit remaining wait budget "
                f"{remaining_budget:.0f}s (maximum {self._max_wait_s:.0f}s)"
            )
            raise self._decline(msg)
        return wait

    def _decline(self, message: str) -> RateLimited:
        self._local_decline_count += 1
        return RateLimited(message)

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


_LOOP_LIMITERS_ATTRIBUTE = "_recon_tool_adaptive_rate_limiters"


def _get_limiter(name: str, **kwargs: object) -> AdaptiveRateLimiter:
    loop = asyncio.get_running_loop()
    table: dict[str, AdaptiveRateLimiter] | None = getattr(loop, _LOOP_LIMITERS_ATTRIBUTE, None)
    if table is None:
        table = {}
        setattr(loop, _LOOP_LIMITERS_ATTRIBUTE, table)
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
