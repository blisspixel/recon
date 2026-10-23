"""Run admission stops before IO and cannot masquerade as empty DNS."""

from __future__ import annotations

import asyncio
from typing import NoReturn

import dns.resolver
import pytest

from recon_tool import resolver
from recon_tool.collection_limits import CollectionBudget, CollectionBudgetExceeded, admit_namespace, collection_budget
from recon_tool.models import SourceResult
from recon_tool.sources import dns_base


class EmptyResolver:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, domain: str, rdtype: str, *, lifetime: float) -> NoReturn:
        assert lifetime > 0
        self.calls.append((domain, rdtype))
        raise dns.resolver.NoAnswer


@pytest.mark.asyncio
async def test_concurrent_dns_calls_reserve_exact_budget_before_resolver_io(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = EmptyResolver()
    monkeypatch.setattr(dns_base, "get_resolver", lambda: fake)
    budget = CollectionBudget(frozenset({"alpha.test"}), 3)
    with collection_budget(budget), dns_base.dns_query_ledger() as ledger:
        results = await asyncio.gather(
            *(dns_base.safe_resolve("alpha.test", "TXT") for _ in range(12)), return_exceptions=True
        )
    assert len(fake.calls) == 3
    assert budget.dns_queries == 3
    assert budget.stopped_reason == "dns_query_budget"
    assert results[:3] == [[], [], []]
    assert all(isinstance(result, CollectionBudgetExceeded) for result in results[3:])
    # The unadmitted calls never became empty or unavailable observations.
    assert ledger.attempted == ledger.clean_responses == 3


@pytest.mark.asyncio
async def test_nested_source_ledgers_share_budget_and_scope_restores(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = EmptyResolver()
    monkeypatch.setattr(dns_base, "get_resolver", lambda: fake)
    budget = CollectionBudget(frozenset({"alpha.test"}), 3)
    with collection_budget(budget), dns_base.dns_query_ledger() as outer:
        await dns_base.safe_resolve("alpha.test", "TXT")
        with dns_base.dns_query_ledger() as inner:
            await dns_base.safe_resolve("alpha.test", "MX")
        await dns_base.safe_resolve("alpha.test", "CNAME")
        with pytest.raises(CollectionBudgetExceeded, match="dns_query_budget"):
            await dns_base.safe_resolve("alpha.test", "NS")
    assert budget.dns_queries == 3
    assert outer.attempted == 2
    assert inner.attempted == 1
    # An ordinary invocation after scope exit has no inherited restriction.
    assert await dns_base.safe_resolve("outside.test", "TXT") == []
    assert len(fake.calls) == 4
    admit_namespace("outside.test")


@pytest.mark.asyncio
async def test_source_exception_isolation_cannot_swallow_run_exhaustion(monkeypatch: pytest.MonkeyPatch) -> None:
    from recon_tool.sources.dns import DNSSource

    fake = EmptyResolver()
    monkeypatch.setattr(dns_base, "get_resolver", lambda: fake)
    budget = CollectionBudget(frozenset({"alpha.test"}), 2)
    with collection_budget(budget), pytest.raises(CollectionBudgetExceeded, match="dns_query_budget"):
        await DNSSource().lookup("alpha.test", skip_ct=True)
    assert len(fake.calls) == 2


@pytest.mark.asyncio
async def test_undeclared_namespace_is_refused_before_source_pool_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_pool() -> NoReturn:
        pytest.fail("source pool construction happened before namespace admission")

    monkeypatch.setattr(resolver, "default_pool", forbidden_pool)
    budget = CollectionBudget(frozenset({"alpha.test"}), 3)
    with collection_budget(budget), pytest.raises(CollectionBudgetExceeded, match="namespace_outside_frozen_frame"):
        await resolver.resolve_tenant("outside.test")
    assert not budget.namespace_attempts
    assert budget.dns_queries == 0


@pytest.mark.asyncio
async def test_durable_start_precedes_source_work_and_repeated_lookup_is_refused() -> None:
    starts: list[str] = []
    calls: list[str] = []

    class Source:
        name = "synthetic"

        async def lookup(self, domain: str, **_kwargs: object) -> SourceResult:
            assert starts == [domain]
            calls.append(domain)
            return SourceResult(source_name=self.name, tenant_id="00000000-0000-4000-8000-000000000001")

    budget = CollectionBudget(frozenset({"alpha.test"}), 3, on_start=starts.append)
    pool = resolver.SourcePool([Source()])
    with collection_budget(budget):
        info, _ = await resolver.resolve_tenant("alpha.test", pool=pool)
        assert info.queried_domain == "alpha.test"
        with pytest.raises(CollectionBudgetExceeded, match="namespace_attempt_budget"):
            await resolver.resolve_tenant("alpha.test", pool=pool)
    assert starts == calls == ["alpha.test"]


@pytest.mark.asyncio
async def test_start_receipt_failure_prevents_source_work(monkeypatch: pytest.MonkeyPatch) -> None:
    def failed_receipt(_domain: str) -> NoReturn:
        raise OSError("synthetic full disk")

    def forbidden_pool() -> NoReturn:
        pytest.fail("lookup IO must not precede a durable start receipt")

    monkeypatch.setattr(resolver, "default_pool", forbidden_pool)
    budget = CollectionBudget(frozenset({"alpha.test"}), 3, on_start=failed_receipt)
    with collection_budget(budget), pytest.raises(CollectionBudgetExceeded, match="start_receipt_unavailable"):
        await resolver.resolve_tenant("alpha.test")
    assert not budget.namespace_attempts
    assert budget.stopped_reason == "start_receipt_unavailable"


def test_budget_cannot_be_replaced_by_nested_scope_and_reentrant_scope_keeps_counts() -> None:
    first = CollectionBudget(frozenset({"alpha.test"}), 2)
    second = CollectionBudget(frozenset({"beta.test"}), 100)
    with collection_budget(first):
        with pytest.raises(ValueError, match="cannot replace"), collection_budget(second):
            pytest.fail("a nested scope expanded the admission budget")
        with collection_budget(first):
            admit_namespace("alpha.test")
        with pytest.raises(CollectionBudgetExceeded, match="namespace_attempt_budget"):
            admit_namespace("alpha.test")


@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_invalid_budget_is_not_silently_coerced(value: int) -> None:
    with pytest.raises(ValueError, match="positive integers"):
        CollectionBudget(frozenset({"alpha.test"}), value)


def test_missing_frame_is_refused() -> None:
    with pytest.raises(ValueError, match="nonempty frozen namespace"):
        CollectionBudget(frozenset(), 1)
