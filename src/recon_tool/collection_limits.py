"""Optional admission limits for explicitly bounded maintainer collection.

Ordinary CLI/library/MCP calls install no budget. The scoped guard limits
top-level lookup coordinates and logical DNS-collector calls, not physical
resolver packets or HTTP transport retries. Exhaustion stops the caller's run
rather than manufacturing empty source observations.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import NoReturn


class CollectionBudgetExceeded(BaseException):
    """Stop an admitted run through ordinary per-source exception isolation.

    Deliberately outside Exception: a budget stop is a run-level control event,
    not a failed provider response that a detector may convert to an empty set.
    The maintainer launcher catches it and preserves streamed partial results.
    """


@dataclass
class CollectionBudget:
    """One shared admission counter inherited by concurrent collection tasks."""

    namespaces: frozenset[str]
    max_dns_queries: int
    on_start: Callable[[str], None] | None = None
    max_attempts_per_namespace: int = 1
    dns_queries: int = field(default=0, init=False)
    namespace_attempts: dict[str, int] = field(default_factory=dict[str, int], init=False)
    stopped_reason: str | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if not self.namespaces or not all(self.namespaces):
            raise ValueError("collection budget needs a nonempty frozen namespace set")
        for value in (self.max_dns_queries, self.max_attempts_per_namespace):
            if type(value) is not int or value < 1:
                raise ValueError("collection query and namespace-attempt limits must be positive integers")

    def _stop(self, reason: str) -> NoReturn:
        self.stopped_reason = reason
        raise CollectionBudgetExceeded(f"Collection stopped: {reason}")

    def admit_namespace(self, domain: str) -> None:
        """Persist the declared start before allowing that lookup's IO."""
        if self.stopped_reason is not None:
            self._stop(self.stopped_reason)
        if domain not in self.namespaces:
            self._stop("namespace_outside_frozen_frame")
        attempts = self.namespace_attempts.get(domain, 0)
        if attempts >= self.max_attempts_per_namespace:
            self._stop("namespace_attempt_budget")
        if self.on_start is not None:
            try:
                self.on_start(domain)
            except Exception as exc:
                self.stopped_reason = "start_receipt_unavailable"
                raise CollectionBudgetExceeded("Collection stopped: start_receipt_unavailable") from exc
        self.namespace_attempts[domain] = attempts + 1

    def admit_dns_query(self) -> None:
        """Reserve a logical collector query before resolver IO begins."""
        if self.stopped_reason is not None:
            self._stop(self.stopped_reason)
        if self.dns_queries >= self.max_dns_queries:
            self._stop("dns_query_budget")
        self.dns_queries += 1


_ACTIVE: ContextVar[CollectionBudget | None] = ContextVar("recon_collection_budget", default=None)


@contextmanager
def collection_budget(budget: CollectionBudget) -> Generator[CollectionBudget]:
    """Install one run budget; nested source ledgers do not replace it."""
    active = _ACTIVE.get()
    if active is not None and active is not budget:
        raise ValueError("cannot replace an active collection budget")
    token = _ACTIVE.set(budget)
    try:
        yield budget
    finally:
        _ACTIVE.reset(token)


def admit_namespace(domain: str) -> None:
    budget = _ACTIVE.get()
    if budget is not None:
        budget.admit_namespace(domain)


def admit_dns_query() -> None:
    budget = _ACTIVE.get()
    if budget is not None:
        budget.admit_dns_query()
