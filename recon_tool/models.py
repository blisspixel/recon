"""Data models for domain intelligence lookup."""

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "ConfidenceLevel",
    "ReconLookupError",
    "SourceResult",
    "TenantInfo",
]


class ConfidenceLevel(str, Enum):
    """How reliable the resolved TenantInfo is based on source agreement."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class SourceResult:
    """Structured output from a single LookupSource."""

    source_name: str
    tenant_id: str | None = None
    display_name: str | None = None
    default_domain: str | None = None
    region: str | None = None
    m365_detected: bool = False
    error: str | None = None
    detected_services: tuple[str, ...] = ()
    # Extended intel fields
    auth_type: str | None = None          # "Federated" or "Managed"
    dmarc_policy: str | None = None       # "reject", "quarantine", "none"
    tenant_domains: tuple[str, ...] = ()  # All domains in the tenant
    detected_slugs: tuple[str, ...] = ()  # Fingerprint slugs that matched
    # Domains discovered from CNAME targets (autodiscover redirects, DKIM
    # delegation) that likely belong to the same organization but weren't
    # in the Autodiscover tenant domain list.
    related_domains: tuple[str, ...] = ()

    # True when crt.sh was unreachable — signals partial subdomain coverage
    crtsh_degraded: bool = False

    @property
    def is_success(self) -> bool:
        """True if this result contains any useful data (identity or services)."""
        return (
            self.tenant_id is not None
            or self.m365_detected
            or len(self.detected_services) > 0
        )

    @property
    def is_complete(self) -> bool:
        """True if this result has all core fields."""
        return all([self.tenant_id, self.display_name, self.default_domain])


@dataclass(frozen=True)
class TenantInfo:
    """Structured tenant information merged from one or more sources.

    tenant_id is None when no M365 tenant was found but DNS services were
    detected. Downstream code should check `if info.tenant_id` or `is not None`.
    """

    # NOTE: tenant_id is Optional — None means "no M365 tenant found, but
    # we still have DNS-based service data worth showing."
    tenant_id: str | None
    display_name: str
    default_domain: str
    queried_domain: str
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    region: str | None = None
    sources: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    slugs: tuple[str, ...] = ()          # Stable fingerprint identifiers
    # Extended intel
    auth_type: str | None = None          # "Federated" or "Managed"
    dmarc_policy: str | None = None       # "reject", "quarantine", "none"
    domain_count: int = 0                 # Number of domains in tenant
    tenant_domains: tuple[str, ...] = ()  # All domains found
    related_domains: tuple[str, ...] = () # Domains inferred from CNAME targets
    insights: tuple[str, ...] = ()        # Derived intelligence signals
    crtsh_degraded: bool = False          # True when crt.sh was unreachable


@dataclass
class ReconLookupError(Exception):
    """Structured error from the resolver.

    Extends Exception via dataclass. Note: dataclass doesn't set Exception.args,
    so str() returns self.message (via __str__) while repr() shows all fields.
    This is intentional — str() is user-facing, repr() is for debugging.
    """

    domain: str
    message: str
    error_type: str

    def __str__(self) -> str:
        return self.message
