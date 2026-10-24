"""Startup-selected DNS authority for lower-trust collection contexts.

The policy is immutable data. A task-local scope binds its resolver to both
DNS collectors and HTTP destination admission without mutating host DNS.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import ipaddress
import json
import os
import re
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass

import certifi
import dns.asyncresolver
import dns.nameserver
import dns.resolver

_POLICY_VERSION = 1
_TLS_NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", re.ASCII)
# Reuse an explicitly configured public service, never substitute a provider
# for an enterprise/stub resolver whose disclosure authority is unknown.
_PUBLIC_SERVICES = (
    (frozenset({"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"}), "cloudflare-dns.com"),
    (frozenset({"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"}), "dns.google"),
)
# Maintainer-approved encrypted default for hosts on any other resolver
# (ADR-0019 amendment). IPv4 bootstraps avoid stalls on IPv4-only networks.
DEFAULT_CALLER_SAFE_SERVERS = ("1.1.1.1", "1.0.0.1")
DEFAULT_CALLER_SAFE_TLS_NAME = "cloudflare-dns.com"


class DnsPolicyUnavailable(RuntimeError):
    """The caller-safe DNS view is disabled or its saved settings are invalid."""


@dataclass(frozen=True, slots=True)
class CollectionPolicy:
    """One process's operator-selected DNS disclosure authority."""

    mode: str
    servers: tuple[str, ...] = ()
    tls_name: str = ""
    available: bool = True
    transport: str = "https"

    @classmethod
    def from_environment(cls, environment: Mapping[str, str], system_servers: tuple[str, ...] = ()) -> CollectionPolicy:
        """Bind saved authority, reuse a configured public service, or use the encrypted default.

        ``RECON_DNS_VIEW=none`` disables DNS collection explicitly. Partial or
        invalid saved settings stay unavailable rather than becoming the default.
        """
        mode = environment.get("RECON_DNS_VIEW", "caller-safe")
        transport = environment.get("RECON_DNS_TRANSPORT", "https")
        if mode == "operator":
            return cls(mode)
        if mode != "caller-safe" or transport not in {"https", "tls"}:
            return cls("unavailable", available=False)
        if "RECON_DNS_SERVERS" not in environment and "RECON_DNS_TLS_NAME" not in environment:
            configured = frozenset(system_servers)
            reused = next(
                ((system_servers, name) for servers, name in _PUBLIC_SERVICES if configured and configured <= servers),
                (DEFAULT_CALLER_SAFE_SERVERS, DEFAULT_CALLER_SAFE_TLS_NAME),
            )
            return cls(mode, *reused, transport=transport)
        raw_servers = environment.get("RECON_DNS_SERVERS", "").split(",")
        tls_name = environment.get("RECON_DNS_TLS_NAME", "").lower()
        try:
            servers = tuple(str(ipaddress.ip_address(value.strip())) for value in raw_servers)
        except ValueError:
            return cls(mode, available=False)
        if not 1 <= len(servers) <= 4 or _TLS_NAME.fullmatch(tls_name) is None or "." not in tls_name:
            return cls(mode, available=False)
        return cls(mode, servers, tls_name, transport=transport)

    @property
    def identity(self) -> str:
        """Bind caches to policy/version without publishing resolver endpoints."""
        encoded = json.dumps(
            [_POLICY_VERSION, self.mode, self.servers, self.tls_name, self.available, self.transport],
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(encoded).hexdigest()


# Read once, before any client request. Reloading catalogs and changing tool
# arguments or the process environment cannot change collection authority.
def _load_host_resolver() -> dns.asyncresolver.Resolver:
    """Keep offline startup available when host DNS configuration is absent."""
    try:
        return dns.asyncresolver.Resolver()
    except (dns.resolver.NoResolverConfiguration, OSError):
        return dns.asyncresolver.Resolver(configure=False)


HOST_RESOLVER = _load_host_resolver()
MCP_COLLECTION_POLICY = CollectionPolicy.from_environment(
    os.environ, tuple(server for server in HOST_RESOLVER.nameservers if isinstance(server, str))
)
OPERATOR_POLICY = CollectionPolicy("operator")


@dataclass(frozen=True, slots=True)
class _CollectionScope:
    policy: CollectionPolicy
    resolver: dns.asyncresolver.Resolver | None


_ACTIVE_SCOPE: contextvars.ContextVar[_CollectionScope | None] = contextvars.ContextVar(
    "recon_collection_scope", default=None
)


def current_policy() -> CollectionPolicy:
    """Return the active authority; trusted CLI/library calls retain host DNS."""
    scope = _ACTIVE_SCOPE.get()
    return scope.policy if scope is not None else OPERATOR_POLICY


@contextmanager
def collection_scope(policy: CollectionPolicy) -> Generator[None]:
    """Bind a fixed DNS view to this task tree and restore it on every exit."""
    resolver = None
    if policy.mode == "caller-safe" and policy.available:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [
            dns.nameserver.DoHNameserver(
                f"https://{policy.tls_name}/dns-query", bootstrap_address=address, verify=certifi.where()
            )
            if policy.transport == "https"
            else dns.nameserver.DoTNameserver(address, hostname=policy.tls_name, verify=certifi.where())
            for address in policy.servers
        ]
    token = _ACTIVE_SCOPE.set(_CollectionScope(policy, resolver))
    try:
        yield
    finally:
        _ACTIVE_SCOPE.reset(token)


def selected_resolver(default: dns.asyncresolver.Resolver) -> dns.asyncresolver.Resolver:
    """Select the configured view, refusing missing policy without fallback."""
    scope = _ACTIVE_SCOPE.get()
    if scope is None or scope.policy.mode == "operator":
        return default
    if scope.resolver is None:
        raise DnsPolicyUnavailable("Caller-safe DNS view is unavailable; configure it at trusted startup")
    return scope.resolver


async def selected_addresses(host: str) -> tuple[str, ...] | None:
    """Resolve HTTP names in the same view; None permits trusted OS resolution.

    Failure of either address family refuses the destination. A complete empty
    response is distinct from unavailable evidence. Public-address admission
    and numeric socket pinning still belong to the existing HTTP transport.
    """
    scope = _ACTIVE_SCOPE.get()
    if scope is None or scope.policy.mode == "operator":
        return None
    selected = scope.resolver
    if selected is None:
        return ()
    try:
        literal = str(ipaddress.ip_address(host))
    except ValueError:
        literal = None
    if literal is not None:
        return (literal,)

    async def addresses(rdtype: str) -> tuple[str, ...]:
        try:
            answer = await selected.resolve(host, rdtype, lifetime=5.0)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ()
        return tuple(str(record) for record in answer)

    try:
        ipv4, ipv6 = await asyncio.gather(addresses("A"), addresses("AAAA"))
    except Exception:
        return ()
    return tuple(dict.fromkeys((*ipv4, *ipv6)))
