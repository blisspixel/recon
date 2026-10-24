"""Local DNS capability reporting, shared by server and doctor diagnostics."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal, cast

from recon_tool.network_policy import CollectionPolicy

DNS_CAPABILITY_PREFIX = "recon.dns_view.v1: "
DNS_SETUP_GUIDE = "https://github.com/blisspixel/recon/blob/main/docs/mcp.md#dns-view-isolation"
DNS_SETUP_NEXT = f"Approve a caller-safe DNS view once in the MCP server settings: {DNS_SETUP_GUIDE}"
DNS_CHECK_NAME = "DNS collection view"


@dataclass(frozen=True)
class DnsReadiness:
    status: Literal["ok", "warn"]
    detail: str
    next: str | None = None


def advertised_dns_capability(policy: CollectionPolicy) -> str:
    """Advertise startup authority without resolver addresses or DNS queries."""
    payload = {
        "mode": policy.mode,
        "available": policy.available,
        "transport": "host" if policy.mode == "operator" else policy.transport,
        "policy_id": policy.identity,
    }
    return DNS_CAPABILITY_PREFIX + json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _capability_payload(instructions: object) -> dict[str, object] | None:
    """Parse one bounded startup declaration without interpreting its values."""
    if not isinstance(instructions, str) or len(instructions) > 65536:
        return None
    lines = [
        line.removeprefix(DNS_CAPABILITY_PREFIX)
        for line in instructions.splitlines()
        if line.startswith(DNS_CAPABILITY_PREFIX)
    ]
    if len(lines) != 1 or len(lines[0]) > 512:
        return None
    try:
        payload = json.loads(lines[0])
    except (ValueError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    fields = cast(dict[str, object], payload)
    if set(fields) != {"mode", "available", "transport", "policy_id"}:
        return None
    return fields


def dns_readiness_from_instructions(instructions: object) -> DnsReadiness:
    """Read a bounded server-advertised capability across both SDK generations.

    Discovery instructions come from the launched process, rather than a guess
    based on the doctor's environment. They are a capability report, not an
    attestation that a remote endpoint is reachable or a client is configured.
    """
    unknown = DnsReadiness(
        "warn",
        "server did not advertise valid DNS readiness; local protocol checks do not establish DNS collection",
        "Update the server installation, then rerun recon mcp doctor",
    )
    fields = _capability_payload(instructions)
    if fields is None:
        return unknown
    mode, available, transport, policy_id = (fields[key] for key in ("mode", "available", "transport", "policy_id"))
    if (
        not isinstance(mode, str)
        or mode not in {"caller-safe", "operator", "unavailable"}
        or type(available) is not bool
        or not isinstance(transport, str)
        or transport not in {"https", "tls", "host"}
        or not isinstance(policy_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", policy_id) is None
    ):
        return unknown
    if not available:
        return DnsReadiness(
            "warn",
            "no approved caller-safe DNS view; DNS-dependent tools are unavailable, "
            "local tools and resources remain usable",
            DNS_SETUP_NEXT,
        )
    if mode == "operator" and transport == "host":
        return DnsReadiness("ok", f"operator DNS view for operator-authorized callers; policy {policy_id[:12]}")
    if mode == "caller-safe" and transport in {"https", "tls"}:
        transport_label = "DNS-over-HTTPS" if transport == "https" else "DNS-over-TLS"
        return DnsReadiness("ok", f"approved caller-safe view ({transport_label}); policy {policy_id[:12]}")
    return unknown


def collection_policy_readiness(policy: CollectionPolicy) -> DnsReadiness:
    """Report the same bound capability for the in-process static doctor."""
    return dns_readiness_from_instructions(advertised_dns_capability(policy))
