"""Stdio server with a stubbed chain resolver for progress tests.

The patch runs only when this file is the program. Importing it must not
change the parent process.
"""

from __future__ import annotations

import asyncio

import httpx

from recon_tool.models import SourceResult, TenantInfo
from recon_tool.resolver import RESOLVE_TIMEOUT, SourcePool


async def _resolve_tenant(
    domain: str,
    pool: SourcePool | None = None,
    client: httpx.AsyncClient | None = None,
    timeout: float = RESOLVE_TIMEOUT,
    skip_ct: bool = False,
    active_probes: bool = False,
) -> tuple[TenantInfo, list[SourceResult]]:
    """Return one synthetic namespace. The pause lets two progress lines through."""
    del pool, client, timeout, skip_ct, active_probes
    await asyncio.sleep(0.6)
    related = ("related.invalid",) if domain == "alpha.invalid" else ()
    info = TenantInfo(
        tenant_id=None,
        display_name="Synthetic",
        default_domain=domain,
        queried_domain=domain,
        related_domains=related,
    )
    return info, []


def _admit(_domain: str) -> bool:
    return True


if __name__ == "__main__":
    # Import the server before patching so package initialization finishes first.
    import recon_tool.chain as chain
    import recon_tool.server.graph as graph
    from recon_tool.server import main

    chain.resolve_tenant = _resolve_tenant
    graph.rate_limit_try_acquire = _admit
    main()
