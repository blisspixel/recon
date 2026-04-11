"""Base protocol for lookup sources."""

from typing import Any, Protocol, runtime_checkable

from recon_tool.models import SourceResult


@runtime_checkable
class LookupSource(Protocol):
    """Protocol that all lookup sources must implement."""

    @property
    def name(self) -> str:
        """Unique string identifier for this source."""
        ...

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        """
        Attempt to resolve tenant information for the given domain.

        Args:
            domain: A validated domain string
            **kwargs: Additional context (e.g., tenant_id from a prior source)

        Returns:
            SourceResult with partial or complete tenant data
        """
        ...
