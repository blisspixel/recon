"""Stdio server with a stubbed chain resolver for progress tests.

The patch runs only when this file is the program. Importing it must not
change the parent process.
"""

from __future__ import annotations

import asyncio

from recon_tool.models import SourceResult, TenantInfo


async def _resolve_tenant(
    domain: str,
    *_unused: object,
    **_ignored: object,
) -> tuple[TenantInfo, list[SourceResult]]:
    """Return one synthetic namespace. The pause lets two progress lines through.

    Positional and keyword arguments match ``resolve_tenant`` so the chain
    caller can pass pool, client, timeout, and probe flags unchanged.
    """
    del _unused, _ignored
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
