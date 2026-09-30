"""Shared RFC 3986 syntax validation for public email-policy declarations.

This does not authorize fetching a URI or validate a scheme's application
semantics. Protocol callers apply their own delimiters and scheme rules;
network callers must still enforce the existing destination safety boundary.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import SplitResult, urlsplit

_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_INVALID_URI_CHAR_RE = re.compile(r"[\x00-\x20\x7f]")
_INVALID_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_URI_PATH_RE = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")
_URI_QUERY_FRAGMENT_RE = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*")
_URI_USERINFO_RE = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:%-]*")
_URI_REG_NAME_RE = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=%-]*")
_IPV_FUTURE_RE = re.compile(r"[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+")
_UPPER_IPV_FUTURE_RE = re.compile(r"(://(?:[^/?#]*@)?\[)V(?=[0-9A-Fa-f]+\.)")
_ASCII_PORT_RE = re.compile(r"[0-9]*")


def _valid_uri_ip_literal(literal: str) -> bool:
    if "%" in literal:
        return False
    try:
        ipaddress.IPv6Address(literal)
        return True
    except ValueError:
        return bool(_IPV_FUTURE_RE.fullmatch(literal))


def _valid_uri_authority(netloc: str) -> bool:
    userinfo, separator, host_port = netloc.rpartition("@")
    if separator and not _URI_USERINFO_RE.fullmatch(userinfo):
        return False
    if host_port.startswith("["):
        close = host_port.find("]")
        suffix = host_port[close + 1 :] if close >= 0 else "invalid"
        valid_suffix = not suffix or (suffix.startswith(":") and bool(_ASCII_PORT_RE.fullmatch(suffix[1:])))
        if close < 0 or not valid_suffix:
            return False
        return _valid_uri_ip_literal(host_port[1:close])
    if "[" in host_port or "]" in host_port:
        return False
    host, separator, port = host_port.rpartition(":")
    if not separator:
        host = host_port
    return (
        ":" not in host
        and (not separator or bool(_ASCII_PORT_RE.fullmatch(port)))
        and bool(_URI_REG_NAME_RE.fullmatch(host))
    )


def parse_email_policy_uri(candidate: str) -> SplitResult | None:
    """Check generic URI syntax without repairing whitespace or bad escapes."""
    if (
        not candidate
        or not candidate.isascii()
        or _INVALID_URI_CHAR_RE.search(candidate)
        or _INVALID_PERCENT_ESCAPE_RE.search(candidate)
        or not _URI_SCHEME_RE.match(candidate)
    ):
        return None
    try:
        parsed = urlsplit(_UPPER_IPV_FUTURE_RE.sub(r"\1v", candidate, count=1))
    except ValueError:
        return None
    components_valid = (
        bool(parsed.scheme)
        and bool(_URI_PATH_RE.fullmatch(parsed.path))
        and bool(_URI_QUERY_FRAGMENT_RE.fullmatch(parsed.query))
        and bool(_URI_QUERY_FRAGMENT_RE.fullmatch(parsed.fragment))
    )
    if not components_valid or (parsed.netloc and not _valid_uri_authority(parsed.netloc)):
        return None
    return parsed
