#!/usr/bin/env python3
"""Guard committed validation artifacts against target-data leaks."""

from __future__ import annotations

import ast
import csv
import ipaddress
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

PRIVATE_PREFIXES = (
    "validation/corpus-private/",
    "validation/runs-private/",
    "validation/local/",
    "validation/live_runs/",
    "validation/agentic_ux/runs/",
    "validation/agentic_ux/local/",
)

SCAN_SUFFIXES = {".csv", ".json", ".md", ".ndjson", ".py", ".txt", ".yaml", ".yml"}
STRUCTURED_SUFFIXES = {".json", ".ndjson", ".yaml", ".yml"}
GIT_FILE_INVENTORY_ARGS = (
    "git",
    "ls-files",
    "--cached",
    "--others",
    "--exclude-standard",
    "-z",
)

ALLOWED_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
}

_RETIRED_TARGET_BRANDS = (
    "con" + "toso",
    "fab" + "rikam",
    "north" + "wind",
    "north" + "windtraders",
    "ada" + "tum",
    "adventure" + "-works",
    "adventure" + " works",
    "tailspin" + "toys",
    "tailspin" + " toys",
    "wingtip" + "toys",
    "wingtip" + " toys",
    "woodgrove" + "bank",
    "woodgrove" + " bank",
    "lit" + "ware",
    "lucerne" + " publishing",
    "pro" + "ware",
    "humongous" + " insurance",
    "trey" + "research",
    "trey" + " research",
    "graphic design" + " institute",
    "consolidated" + " messenger",
)
RETIRED_TARGET_BRAND_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(value) for value in _RETIRED_TARGET_BRANDS) + r")\b",
    re.IGNORECASE,
)
_RETIRED_PLACEHOLDER_LOWER = "ac" + "me"
_RETIRED_PLACEHOLDER_TITLE = "Ac" + "me"
_RETIRED_PLACEHOLDER_UPPER = "AC" + "ME"
_UPPER_PLACEHOLDER_TARGET_SUFFIX = (
    r"(?:\.[a-z0-9]|[- ](?i:bank|cloud|company|corp(?:oration)?|email|group|holdings|inc|labs|llc|"
    r"ltd|security|sso)\b)"
)
RETIRED_PLACEHOLDER_RE = re.compile(
    r"(?<!_)\b(?:"
    + re.escape(_RETIRED_PLACEHOLDER_LOWER)
    + "|"
    + re.escape(_RETIRED_PLACEHOLDER_TITLE)
    + "|"
    + re.escape(_RETIRED_PLACEHOLDER_UPPER)
    + r"(?="
    + _UPPER_PLACEHOLDER_TARGET_SUFFIX
    + ")"
    + r")\b(?!-challenge)"
)

_DOMAIN_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_TLD = r"[a-z](?:[a-z0-9-]{0,60}[a-z0-9])"
_DOMAIN_PATTERN = rf"{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*\.{_DOMAIN_TLD}"
DOMAIN_RE = re.compile(rf"(?i)\b{_DOMAIN_PATTERN}\b")
PATH_DOMAIN_RE = re.compile(rf"(?i)^{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*\.{_DOMAIN_TLD}$")
_TARGET_FIELD_NAMES = (
    r"(?:apex|apex[_-]?domain|default[_-]?domain|domain|hostname|host|input[_-]?domain|"
    r"queried[_-]?domain|target|target[_-]?domain|target[_-]?hostname)"
)
_TENANT_FIELD_NAMES = r"[a-z0-9_-]*tenant[_-]?id"
TARGET_FIELD_RE = re.compile(
    rf"(?i)[\"'`]?\b{_TARGET_FIELD_NAMES}\b[\"'`]?"
    rf"\s*[:=]\s*[\"'`]?({_DOMAIN_PATTERN})[\"'`]?"
)
PY_TARGET_FIELD_RE = re.compile(rf"(?i)[\"']?\b{_TARGET_FIELD_NAMES}\b[\"']?\s*[:=]\s*([\"'])({_DOMAIN_PATTERN})\1")
_RECON_EXECUTABLE_PATTERN = r"(?:uv[ \t]+run[ \t]+)?(?:recon|(?:python(?:3(?:\.\d+)?)?|py)[ \t]+-m[ \t]+recon_tool)"
RECON_COMMAND_PREFIX_RE = re.compile(rf"(?i)\b{_RECON_EXECUTABLE_PATTERN}\b")
RECON_COMMAND_RE = re.compile(
    rf"(?i)\b{_RECON_EXECUTABLE_PATTERN}[ \t]+"
    rf"(?!(?:analyze|batch|completion|discover|doctor|fingerprints|mcp|profiles?|signals)\b)"
    rf"(?:(?:lookup|delta)[ \t]+|cache[ \t]+(?:show|clear)[ \t]+)?"
    rf"(?:[^\s`\"';|&]+[ \t]+)*?[\"']?(?:https?://)?(?:www\.)?({_DOMAIN_PATTERN})\b"
)
DNS_OWNER_ARROW_RE = re.compile(rf"(?i)(?:^|[|`\s])({_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*\.{_DOMAIN_TLD})\s*(?:->|→)")
DNS_RECORD_ROW_RE = re.compile(
    rf"(?i)^\s*(?:(?:>\s*)|(?:(?:[-*]|\d+[.)])\s+))*[\"'`]?"
    rf"({_DOMAIN_PATTERN})\.?[\"'`]?\s+(?:[0-9]+\s+)?(?:IN\s+)?"
    r"(A|AAAA|CAA|CNAME|MX|NS|SRV|TXT)\s+(.+?)\s*$"
)
OWNERLESS_TXT_ROW_RE = re.compile(r"^\s*(?:(?:>\s*)|(?:[-*]\s+))*TXT\s+(.+?)\s*$")
HEADING_RE = re.compile(r"^(#{2,6})\s+(.+?)\s*$")
CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
TENANT_VALUE_RE = re.compile(
    rf"(?i)[\"'`]?\b{_TENANT_FIELD_NAMES}\b[\"'`]?\s*[:=]\s*[\"'`]?([^\s\"'`,}}]+)",
)
PY_TENANT_VALUE_RE = re.compile(
    rf"(?i)[\"']?\b{_TENANT_FIELD_NAMES}\b[\"']?\s*[:=]\s*([\"'])([^\"']+)\1",
)
PROSE_DISPLAY_VALUE_RE = re.compile(
    r"(?i)[\"'`]?\bdisplay[_-]?name\b[\"'`]?\s*[:=]\s*[\"'`]?([^\"'`,}\n]+)",
)
PROSE_ORGANIZATION_VALUE_RE = re.compile(
    r"(?i)[\"'`]?\b(?:bimi[_-]?org|company|company[_-]?name|customer|customer[_-]?name|organization|"
    r"organization[_-]?name)\b[\"'`]?"
    r"\s*[:=]\s*[\"'`]?([^\"'`,}\n]+)",
)
PY_DISPLAY_VALUE_RE = re.compile(
    r"(?i)[\"']?\bdisplay[_-]?name\b[\"']?\s*[:=]\s*([\"'])([^\"']+)\1",
)
PY_ORGANIZATION_VALUE_RE = re.compile(
    r"(?i)[\"']?\b(?:bimi[_-]?org|company|company[_-]?name|customer|customer[_-]?name|organization|"
    r"organization[_-]?name)\b[\"']?"
    r"\s*[:=]\s*([\"'])([^\"']+)\1",
)
VERIFICATION_VALUE_RE = re.compile(
    r"(?i)\b(?:MS=|[a-z0-9_-]+-(?:domain|site)-verification(?:-[a-z0-9_-]+)?=)"
    r"([^\"'`,;|}\n]+)"
)
VERIFICATION_SENTINEL_RE = re.compile(r"^synthetic-(?:domain-token|ms-token|token)-[0-9]{3}$")
CONTINUED_IDENTITY_FIELD_RE = re.compile(
    r"^\s*(?:(?:>\s*)|(?:(?:[-*]|\d+[.)])\s+))*[\"'`]?"
    r"([a-z][a-z0-9_-]*)[\"'`]?\s*[:=]\s*$",
    re.IGNORECASE,
)
PROSE_IDENTITY_FIELD_RE = re.compile(
    r"^\s*(?:(?:>\s*)|(?:(?:[-*]|\d+[.)])\s+))*[\"'`]?"
    r"([a-z][a-z0-9_-]*)[\"'`]?\s*[:=]\s*(.+?)\s*$",
    re.IGNORECASE,
)
MARKDOWN_LIST_ITEM_RE = re.compile(r"^\s*(?:>\s*)*(?:[-*]|\d+[.)])\s+")
MARKDOWN_PREFIX_RE = re.compile(r"^\s*(?:(?:>\s*)|(?:(?:[-*]|\d+[.)])\s+))*")

DOMAIN_VALUE_KEYS = {
    "apex",
    "apex_domain",
    "default_domain",
    "domain",
    "host",
    "hostname",
    "input_domain",
    "queried_domain",
    "subdomain",
    "target",
    "target_domain",
    "target_hostname",
}
DOMAIN_LIST_KEYS = {
    "chain",
    "members",
    "names",
    "peer",
    "peers",
    "related_domains",
    "tenant_domains",
    "wildcard_sibling_clusters",
}
IP_VALUE_KEYS = {"address", "addresses", "ip", "ips"}
NONPUBLIC_CONTAINER_KEYS = {
    "bimi_identity",
    "evidence_conflicts",
    "lexical_observations",
    "shared_display_name",
    "shared_tenant",
    "shared_verification_tokens",
    "site_verification_tokens",
    "unclassified_cname_chains",
    "unclassified_dns_observations",
}
NONPUBLIC_IDENTITY_KEYS = {
    "bimi_org",
    "company",
    "company_name",
    "customer",
    "customer_name",
    "organization",
    "organization_name",
}
IDENTITY_FIELD_KEYS = (
    DOMAIN_VALUE_KEYS
    | DOMAIN_LIST_KEYS
    | IP_VALUE_KEYS
    | NONPUBLIC_CONTAINER_KEYS
    | NONPUBLIC_IDENTITY_KEYS
    | {"display_name", "raw_value", "tenant_id"}
)
DISPLAY_NAME_RE = re.compile(r"^Synthetic (?:Dense Namespace|Scenario (?:[0-9]{3}|[0-9]{12}))$")
TENANT_ID_RE = re.compile(r"^synthetic-(?:dense-tenant|scenario-(?:[0-9]{3}|[0-9]{12}))$")
CSV_SCHEMAS = {
    "validation/aggregate/synthetic_groups.csv": ("domain", "label"),
}
YAML_SCHEMAS: set[str] = set()
CSV_ALLOWED_VALUES = {
    "validation/aggregate/synthetic_groups.csv": {"label": {"fintech", "healthcare", "saas"}},
}
PROVIDER_REFERENCE_DOMAIN_RES = (
    re.compile(r"^synthetic-[a-z0-9-]+\.mail\.protection\.outlook\.com$", re.IGNORECASE),
    re.compile(r"^rua\.agari\.com$", re.IGNORECASE),
    re.compile(r"^synthetic-[a-z0-9-]+\.(?:edgekey\.net|akamaiedge\.net|akamai\.net)$", re.IGNORECASE),
    re.compile(r"^(?:trafficmanager\.net|azurefd\.net|t-msedge\.net)$", re.IGNORECASE),
    re.compile(r"^fly\.io$", re.IGNORECASE),
    re.compile(r"^(?:microsoftonline\.com|graph\.microsoft\.com)$", re.IGNORECASE),
    re.compile(r"^crt\.sh$", re.IGNORECASE),
)
DOCUMENTATION_IP_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
_IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
IPV4_RE = re.compile(rf"(?<![0-9.]){_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}}(?![0-9.])")


def _is_root_domain_dump(path: str) -> bool:
    return "/" not in path and path.casefold().endswith(".json")


def _is_root_scan_dump(path: str) -> bool:
    folded = path.casefold()
    return "/" not in path and folded.startswith("sc-") and folded.endswith(".json")


def _has_target_path_component(path: str) -> bool:
    normalized = path.replace("\\", "/")
    if not normalized.casefold().startswith("validation/"):
        return False
    parts = normalized.split("/")[1:]
    for index, part in enumerate(parts):
        candidate = Path(part).stem if index == len(parts) - 1 else part
        if PATH_DOMAIN_RE.fullmatch(candidate) and not _is_allowed_domain(candidate):
            return True
    return False


def _has_retired_target_example(value: str) -> bool:
    return RETIRED_TARGET_BRAND_RE.search(value) is not None or RETIRED_PLACEHOLDER_RE.search(value) is not None


def _safe_display_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    folded = normalized.casefold()
    if _has_retired_target_example(normalized) or any(ord(character) < 32 for character in normalized):
        return "[redacted]"
    for prefix in PRIVATE_PREFIXES:
        if folded.startswith(prefix.casefold()):
            return f"{prefix}[redacted]"
    if _is_root_domain_dump(normalized) or _is_root_scan_dump(normalized) or _has_target_path_component(normalized):
        return "validation/[redacted]" if folded.startswith("validation/") else "[redacted]"
    if folded.startswith("validation/"):
        return normalized if normalized in _head_validation_paths() else "validation/[redacted]"
    return normalized


@dataclass(frozen=True)
class Violation:
    path: str
    detail: str
    line: int | None = None

    def render(self) -> str:
        safe_path = _safe_display_path(self.path)
        location = safe_path if self.line is None else f"{safe_path}:{self.line}"
        return f"{location}: {self.detail}"


def _tracked_files(root: Path = ROOT) -> list[str]:
    result = subprocess.run(  # noqa: S603 - fixed developer-tool argv
        list(GIT_FILE_INVENTORY_ARGS),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        msg = result.stderr.strip() or "git ls-files failed"
        raise RuntimeError(msg)
    return parse_git_file_inventory(result.stdout)


def parse_git_file_inventory(output: str) -> list[str]:
    """Parse the NUL-delimited candidate inventory without losing odd filenames."""
    return [path.replace("\\", "/") for path in output.split("\0") if path]


@lru_cache(maxsize=1)
def _head_validation_paths() -> frozenset[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "-z", "HEAD", "--", "validation"],  # noqa: S607
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return frozenset()
    return frozenset(parse_git_file_inventory(result.stdout))


def _is_allowed_domain(domain: str) -> bool:
    normalized = domain.lower().strip(".")
    if normalized.endswith((".test", ".invalid")):
        return True
    return normalized in ALLOWED_DOMAINS or any(normalized.endswith(f".{allowed}") for allowed in ALLOWED_DOMAINS)


def is_allowed_public_domain(domain: str) -> bool:
    """Return whether a domain is approved for public examples and fixtures."""
    return _is_allowed_domain(domain)


def _is_allowed_raw_domain(domain: str) -> bool:
    return _is_allowed_domain(domain) or any(pattern.fullmatch(domain) for pattern in PROVIDER_REFERENCE_DOMAIN_RES)


def _looks_like_domain_line(line: str) -> str | None:
    stripped = line.strip().strip('"').strip("'").strip("`")
    if not stripped or stripped.startswith("#"):
        return None
    return stripped.lower() if DOMAIN_RE.fullmatch(stripped) else None


def _should_scan_content(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return normalized.casefold().startswith("validation/") and Path(normalized).suffix.casefold() in SCAN_SUFFIXES


def _iter_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from _iter_strings(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            yield from _iter_strings(nested)


def _iter_unkeyed_strings(value: object):
    """Yield scalar list content while leaving mappings to keyed recursion."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for nested in value:
            if not isinstance(nested, dict):
                yield from _iter_unkeyed_strings(nested)


def _iter_ip_addresses(value: object):
    for item in _iter_strings(value):
        for candidate in IPV4_RE.findall(item):
            yield ipaddress.ip_address(candidate)
        for candidate in re.findall(r"[0-9A-Fa-f:.]+", item):
            if "." in candidate or ":" not in candidate:
                continue
            try:
                yield ipaddress.ip_address(candidate)
            except ValueError:
                continue


def _is_documentation_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address.version == network.version and address in network for network in DOCUMENTATION_IP_NETWORKS)


def _normalize_key(key: object) -> str:
    with_boundaries = CAMEL_BOUNDARY_RE.sub("_", str(key).strip())
    return re.sub(r"[\s-]+", "_", with_boundaries).casefold()


def _is_tenant_identifier_key(key: str) -> bool:
    return key == "tenant_id" or key.endswith("_tenant_id")


def _domain_identity_violation_detail(key: str, value: object) -> str | None:
    if key in DOMAIN_VALUE_KEYS:
        domains = [match.group(0) for item in _iter_strings(value) for match in DOMAIN_RE.finditer(item)]
        if any(not _is_allowed_domain(domain) for domain in domains):
            return f"{key} is not reserved or synthetic"
        if value is not None and not isinstance(value, str):
            return f"{key} has an invalid identity field shape"
        if isinstance(value, str) and value and PATH_DOMAIN_RE.fullmatch(value.strip().strip(".")) is None:
            return f"{key} has an invalid identity field shape"
    if key in DOMAIN_LIST_KEYS:
        strings = list(_iter_strings(value))
        domains = [match.group(0) for item in strings for match in DOMAIN_RE.finditer(item)]
        if any(not _is_allowed_domain(domain) for domain in domains):
            return f"{key} contains a non-reserved domain"
        if any(
            item.strip() and PATH_DOMAIN_RE.fullmatch(item.strip().removeprefix("*.").strip(".")) is None
            for item in strings
        ):
            return f"{key} contains non-domain identity detail"
    return None


def _is_disclosure_safe_raw_value(value: str) -> bool:
    stripped = value.strip()
    try:
        address = ipaddress.ip_address(stripped)
    except ValueError:
        address = None
    if address is not None:
        return _is_documentation_ip(address)
    if re.fullmatch(r"(?i)v=DMARC1;\s*p=(?:none|quarantine|reject)", stripped):
        return True
    if stripped in {
        "FederationBrandName=Synthetic Dense Namespace",
        "NameSpaceType=Managed",
        "rua=mailto:synthetic@rua.agari.com",
        "tenant_id=synthetic-dense-tenant",
    }:
        return True
    verification = VERIFICATION_VALUE_RE.fullmatch(stripped)
    if verification is not None and VERIFICATION_SENTINEL_RE.fullmatch(verification.group(1).strip().casefold()):
        return True
    domains = [match.group(0) for match in DOMAIN_RE.finditer(stripped)]
    if not domains or any(not _is_allowed_raw_domain(domain) for domain in domains):
        return False
    residue = DOMAIN_RE.sub("", stripped)
    return re.fullmatch(r"[\s0-9,*.:>\-]*", residue) is not None


def _record_identity_violation_detail(key: str, value: object) -> str | None:
    if key == "raw_value":
        domains = [match.group(0) for item in _iter_strings(value) for match in DOMAIN_RE.finditer(item)]
        if any(not _is_allowed_raw_domain(domain) for domain in domains):
            return "raw_value contains a non-reserved domain"
        if value is not None and not isinstance(value, str):
            return "raw_value has an invalid identity field shape"
        if any(not _is_documentation_ip(address) for address in _iter_ip_addresses(value)):
            return "raw_value contains a non-documentation IP address"
        if isinstance(value, str) and not _is_disclosure_safe_raw_value(value):
            return "raw_value is outside the disclosure-safe synthetic grammar"
    if key in IP_VALUE_KEYS and any(not _is_documentation_ip(address) for address in _iter_ip_addresses(value)):
        return f"{key} contains a non-documentation IP address"
    return None


def _named_identity_violation_detail(key: str, value: object) -> str | None:
    if (
        key == "display_name"
        and value is not None
        and (not isinstance(value, str) or DISPLAY_NAME_RE.fullmatch(value) is None)
    ):
        return "display_name is not a constrained synthetic sentinel"
    if (
        _is_tenant_identifier_key(key)
        and value is not None
        and (not isinstance(value, str) or TENANT_ID_RE.fullmatch(value) is None)
    ):
        return "tenant_id is not a constrained synthetic sentinel"
    if key in NONPUBLIC_CONTAINER_KEYS and value:
        return f"{key} retains nonpublishable identity detail"
    if key in NONPUBLIC_IDENTITY_KEYS and value:
        return f"{key} retains nonpublishable organization detail"
    return None


def _identity_violation_detail(key: str, value: object) -> str | None:
    for checker in (
        _domain_identity_violation_detail,
        _record_identity_violation_detail,
        _named_identity_violation_detail,
    ):
        detail = checker(key, value)
        if detail is not None:
            return detail
    return None


def _append_identity_violations(
    violations: list[Violation],
    path: str,
    value: object,
) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            raw_key = str(key).strip()
            normalized_key = _normalize_key(key)
            key_domains = [match.group(0) for match in DOMAIN_RE.finditer(raw_key)]
            if any(not _is_allowed_raw_domain(domain) for domain in key_domains):
                violations.append(Violation(path, "mapping key contains a non-reserved domain"))
            detail = _identity_violation_detail(normalized_key, nested)
            if detail is not None:
                violations.append(Violation(path, detail))
            elif isinstance(nested, (str, list)):
                domains = [
                    match.group(0) for item in _iter_unkeyed_strings(nested) for match in DOMAIN_RE.finditer(item)
                ]
                if any(not _is_allowed_raw_domain(domain) for domain in domains):
                    violations.append(Violation(path, "structured field contains a non-reserved domain"))
                if any(not _is_documentation_ip(address) for address in _iter_ip_addresses(nested)):
                    violations.append(Violation(path, "structured field contains a non-documentation IP address"))
            _append_identity_violations(violations, path, nested)
    elif isinstance(value, list):
        for nested in value:
            _append_identity_violations(violations, path, nested)


class _DuplicateMappingKeyError(ValueError):
    """Raised when structured validation data repeats a normalized key."""


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    seen: set[str] = set()
    for key, value in pairs:
        normalized = _normalize_key(key)
        if normalized in seen:
            raise _DuplicateMappingKeyError
        seen.add(normalized)
        result[key] = value
    return result


def _yaml_has_duplicate_keys(node: yaml.Node) -> bool:
    if isinstance(node, yaml.MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            normalized = _normalize_key(getattr(key_node, "value", ""))
            if normalized in seen or _yaml_has_duplicate_keys(value_node):
                return True
            seen.add(normalized)
    elif isinstance(node, yaml.SequenceNode):
        return any(_yaml_has_duplicate_keys(item) for item in node.value)
    return False


def _structured_root_is_mapping_records(value: object) -> bool:
    return isinstance(value, dict) or (isinstance(value, list) and all(isinstance(item, dict) for item in value))


def _structured_violations(path: str, lines: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    suffix = Path(path).suffix.lower()
    text = "\n".join(lines)
    try:
        if suffix == ".json":
            values = [json.loads(text, object_pairs_hook=_unique_json_object)]
        elif suffix == ".ndjson":
            values = [json.loads(line, object_pairs_hook=_unique_json_object) for line in lines if line.strip()]
        else:
            nodes = list(yaml.compose_all(text))
            if any(node is not None and _yaml_has_duplicate_keys(node) for node in nodes):
                return [Violation(path, "structured validation artifact contains a duplicate mapping key")]
            values = list(yaml.safe_load_all(text))
    except _DuplicateMappingKeyError:
        return [Violation(path, "structured validation artifact contains a duplicate mapping key")]
    except (json.JSONDecodeError, yaml.YAMLError, RecursionError):
        format_name = "JSON" if suffix in {".json", ".ndjson"} else "YAML"
        return [Violation(path, f"structured validation artifact is not valid {format_name}")]
    if suffix in {".yaml", ".yml"} and path not in YAML_SCHEMAS:
        violations.append(Violation(path, "tracked validation YAML schema is not approved"))
    for value in values:
        if not _structured_root_is_mapping_records(value):
            violations.append(Violation(path, "structured validation artifact root is not mapping records"))
        _append_identity_violations(violations, path, value)
    return violations


def _csv_violations(path: str, lines: list[str]) -> list[Violation]:
    expected_fields = CSV_SCHEMAS.get(path)
    if expected_fields is None:
        return [Violation(path, "tracked validation CSV schema is not approved")]
    try:
        reader = csv.DictReader(lines)
        if reader.fieldnames is None:
            return [Violation(path, "structured validation artifact has an invalid CSV header")]
        normalized_fields = [field.lstrip("\ufeff").strip().casefold() for field in reader.fieldnames]
        if tuple(normalized_fields) != expected_fields:
            return [Violation(path, "structured validation artifact has an invalid CSV header")]
        rows = list(reader)
    except csv.Error:
        return [Violation(path, "structured validation artifact is not valid CSV")]

    violations: list[Violation] = []
    for row in rows:
        if None in row or any(value is None for value in row.values()):
            violations.append(Violation(path, "structured validation artifact has an invalid CSV row"))
            continue
        normalized_row = {str(key).lstrip("\ufeff").strip().casefold(): value for key, value in row.items()}
        _append_identity_violations(violations, path, normalized_row)
        for key, allowed in CSV_ALLOWED_VALUES.get(path, {}).items():
            if normalized_row.get(key) not in allowed:
                violations.append(Violation(path, f"CSV {key} value is outside the approved aggregate vocabulary"))
    return violations


def _sensitive_value_violations(line: str, *, python_source: bool = False) -> list[str]:
    details: list[str] = []
    if UUID_RE.search(line):
        details.append("UUID-shaped identifier is tracked")
    tenant_pattern = PY_TENANT_VALUE_RE if python_source else TENANT_VALUE_RE
    for tenant_match in tenant_pattern.finditer(line):
        tenant_value = tenant_match.group(2 if python_source else 1)
        normalized_tenant = tenant_value.casefold()
        allowed = (
            normalized_tenant in {"null", "none"}
            or (python_source and normalized_tenant.startswith("synthetic-"))
            or (not python_source and TENANT_ID_RE.fullmatch(normalized_tenant) is not None)
        )
        if not allowed:
            details.append("tenant identifier value is not an explicit synthetic sentinel")
            break
    for verification_match in VERIFICATION_VALUE_RE.finditer(line):
        verification_value = verification_match.group(1).strip().casefold()
        if VERIFICATION_SENTINEL_RE.fullmatch(verification_value) is None:
            details.append("verification-token-shaped value is tracked")
            break
    return details


_MISSING_LITERAL = object()


@dataclass(frozen=True)
class _LiteralAlternatives:
    values: tuple[object, ...]


def _literal_candidates(value: object) -> tuple[object, ...]:
    return value.values if isinstance(value, _LiteralAlternatives) else (value,)


def _collapse_literal_candidates(values: Sequence[object]) -> object:
    unique: list[object] = []
    for value in values:
        if not any(type(value) is type(existing) and value == existing for existing in unique):
            unique.append(value)
        if len(unique) > 32:
            return _MISSING_LITERAL
    if not unique:
        return _MISSING_LITERAL
    return unique[0] if len(unique) == 1 else _LiteralAlternatives(tuple(unique))


def _merge_literal_alternatives(current: object, candidate: object) -> object:
    if current is _MISSING_LITERAL:
        return candidate
    if candidate is _MISSING_LITERAL:
        return current
    return _collapse_literal_candidates([*_literal_candidates(current), *_literal_candidates(candidate)])


def _python_add_literal(node: ast.BinOp, constants: dict[str, object] | None) -> object:
    left = _python_literal(node.left, constants)
    right = _python_literal(node.right, constants)
    if left is _MISSING_LITERAL or right is _MISSING_LITERAL:
        return _MISSING_LITERAL
    combinations = [
        left_value + right_value
        for left_value in _literal_candidates(left)
        for right_value in _literal_candidates(right)
        if isinstance(left_value, str) and isinstance(right_value, str)
    ]
    return _collapse_literal_candidates(combinations)


def _python_fstring_literal(node: ast.JoinedStr, constants: dict[str, object] | None) -> object:
    rendered = [""]
    for part in node.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            candidates = (part.value,)
        elif isinstance(part, ast.FormattedValue):
            value = _python_literal(part.value, constants)
            if value is _MISSING_LITERAL:
                return _MISSING_LITERAL
            candidates = tuple(
                str(item) for item in _literal_candidates(value) if isinstance(item, (str, int, float, bool))
            )
            if not candidates:
                return _MISSING_LITERAL
        else:
            return _MISSING_LITERAL
        rendered = [prefix + suffix for prefix in rendered for suffix in candidates]
        if len(rendered) > 32:
            return _MISSING_LITERAL
    return _collapse_literal_candidates(rendered)


def _python_literal(node: ast.AST, constants: dict[str, object] | None = None) -> object:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        if isinstance(node, ast.Name) and constants is not None:
            return constants.get(node.id, _MISSING_LITERAL)
        if isinstance(node, ast.NamedExpr):
            return _python_literal(node.value, constants)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return _python_add_literal(node, constants)
        if isinstance(node, ast.JoinedStr):
            return _python_fstring_literal(node, constants)
        return _MISSING_LITERAL


_PYTHON_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_PYTHON_CONDITIONAL_NODES = (
    ast.AsyncFor,
    ast.AsyncWith,
    ast.For,
    ast.If,
    ast.Match,
    ast.Try,
    ast.TryStar,
    ast.While,
    ast.With,
)


@dataclass(frozen=True)
class _PythonScopeIndex:
    scope_by_node: dict[ast.AST, ast.AST]
    parent_by_scope: dict[ast.AST, ast.AST]
    conditional_by_node: dict[ast.AST, bool]


def _python_scope_index(tree: ast.AST) -> _PythonScopeIndex:
    scope_by_node: dict[ast.AST, ast.AST] = {}
    parent_by_scope: dict[ast.AST, ast.AST] = {}
    conditional_by_node: dict[ast.AST, bool] = {}

    def visit(node: ast.AST, scope: ast.AST, conditional: bool) -> None:
        scope_by_node[node] = scope
        conditional_by_node[node] = conditional
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            outer_children = [*node.decorator_list, *node.args.defaults]
            outer_children.extend(default for default in node.args.kw_defaults if default is not None)
            if node.returns is not None:
                outer_children.append(node.returns)
            for child in outer_children:
                visit(child, scope, conditional)
            parent_by_scope[node] = scope
            for statement in node.body:
                visit(statement, node, False)
            return
        if isinstance(node, ast.Lambda):
            for default in [*node.args.defaults, *(item for item in node.args.kw_defaults if item is not None)]:
                visit(default, scope, conditional)
            parent_by_scope[node] = scope
            visit(node.body, node, False)
            return
        if isinstance(node, ast.ClassDef):
            for child in [*node.decorator_list, *node.bases, *(keyword.value for keyword in node.keywords)]:
                visit(child, scope, conditional)
            parent_by_scope[node] = scope
            for statement in node.body:
                visit(statement, node, False)
            return
        child_conditional = conditional or isinstance(node, _PYTHON_CONDITIONAL_NODES)
        for child in ast.iter_child_nodes(node):
            visit(child, scope, child_conditional)

    visit(tree, tree, False)
    return _PythonScopeIndex(scope_by_node, parent_by_scope, conditional_by_node)


def _scope_parameter_defaults(scope: ast.AST, outer: dict[str, object]) -> tuple[set[str], dict[str, object]]:
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return set(), {}
    positional = [*scope.args.posonlyargs, *scope.args.args]
    names = {argument.arg for argument in positional}
    names.update(argument.arg for argument in scope.args.kwonlyargs)
    if scope.args.vararg is not None:
        names.add(scope.args.vararg.arg)
    if scope.args.kwarg is not None:
        names.add(scope.args.kwarg.arg)
    defaults: dict[str, object] = {}
    positional_defaults = positional[-len(scope.args.defaults) :] if scope.args.defaults else []
    for argument, default in zip(positional_defaults, scope.args.defaults, strict=True):
        value = _python_literal(default, outer)
        if value is not _MISSING_LITERAL:
            defaults[argument.arg] = value
    for argument, default in zip(scope.args.kwonlyargs, scope.args.kw_defaults, strict=True):
        if default is None:
            continue
        value = _python_literal(default, outer)
        if value is not _MISSING_LITERAL:
            defaults[argument.arg] = value
    return names, defaults


def _apply_python_assignment(
    constants: dict[str, object],
    targets: Sequence[ast.expr],
    value_node: ast.AST | None,
    *,
    conditional: bool,
) -> None:
    value = _python_literal(value_node, constants) if value_node is not None else _MISSING_LITERAL
    for target in targets:
        if not isinstance(target, ast.Name):
            continue
        if conditional:
            merged = _merge_literal_alternatives(constants.get(target.id, _MISSING_LITERAL), value)
            if merged is not _MISSING_LITERAL:
                constants[target.id] = merged
        elif value is _MISSING_LITERAL:
            constants.pop(target.id, None)
        else:
            constants[target.id] = value


def _python_constant_snapshots(
    tree: ast.AST,
    field_nodes: Sequence[ast.expr],
    index: _PythonScopeIndex | None = None,
) -> dict[tuple[ast.AST, int, int], dict[str, object]]:
    index = index or _python_scope_index(tree)
    events: dict[ast.AST, list[tuple[int, int, tuple[ast.expr, ...], ast.AST | None, bool]]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = tuple(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            targets = (node.target,)
        else:
            continue
        scope = index.scope_by_node[node]
        events.setdefault(scope, []).append(
            (node.lineno, node.col_offset, targets, node.value, index.conditional_by_node[node])
        )
    requests: dict[ast.AST, set[tuple[int, int]]] = {}
    for node in field_nodes:
        requests.setdefault(index.scope_by_node[node], set()).add((node.lineno, node.col_offset))

    scopes = {tree, *index.parent_by_scope}
    depth: dict[ast.AST, int] = {tree: 0}

    def scope_depth(scope: ast.AST) -> int:
        if scope not in depth:
            depth[scope] = scope_depth(index.parent_by_scope[scope]) + 1
        return depth[scope]

    for scope in scopes:
        scope_depth(scope)

    final_constants: dict[ast.AST, dict[str, object]] = {}
    snapshots: dict[tuple[ast.AST, int, int], dict[str, object]] = {}
    for scope in sorted(scopes, key=lambda item: (depth.get(item, 0), getattr(item, "lineno", 0))):
        parent = index.parent_by_scope.get(scope)
        constants = final_constants[parent].copy() if parent is not None else {}
        local_names = {
            target.id
            for _line, _column, targets, _value, _conditional in events.get(scope, [])
            for target in targets
            if isinstance(target, ast.Name)
        }
        parameter_names, defaults = _scope_parameter_defaults(scope, constants)
        for name in local_names | parameter_names:
            constants.pop(name, None)
        constants.update(defaults)

        ordered = sorted(events.get(scope, []), key=lambda item: (item[0], item[1]))
        assignment_index = 0
        for requested_position in sorted(requests.get(scope, set())):
            while assignment_index < len(ordered) and ordered[assignment_index][:2] < requested_position:
                _line, _column, targets, value_node, conditional = ordered[assignment_index]
                _apply_python_assignment(constants, targets, value_node, conditional=conditional)
                assignment_index += 1
            snapshots[(scope, *requested_position)] = constants.copy()
        while assignment_index < len(ordered):
            _line, _column, targets, value_node, conditional = ordered[assignment_index]
            _apply_python_assignment(constants, targets, value_node, conditional=conditional)
            assignment_index += 1
        final_constants[scope] = constants
    return snapshots


def _python_target_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        value = _python_literal(node.slice)
        return value if isinstance(value, str) else None
    return None


def _python_assignment_fields(node: ast.Assign):
    for target in node.targets:
        key = _python_target_key(target)
        if key is not None:
            yield key, node.value, node.lineno


def _python_annotated_field(node: ast.AnnAssign):
    key = _python_target_key(node.target)
    if key is not None and node.value is not None:
        yield key, node.value, node.lineno


def _python_dict_fields(node: ast.Dict):
    for key_node, value_node in zip(node.keys, node.values, strict=True):
        if key_node is None:
            continue
        key = _python_literal(key_node)
        if isinstance(key, str):
            yield key, value_node, key_node.lineno


def _python_call_fields(node: ast.Call):
    for keyword in node.keywords:
        if keyword.arg is not None:
            yield keyword.arg, keyword.value, keyword.value.lineno


def _python_fields_for_node(node: ast.AST):
    if isinstance(node, ast.Assign):
        yield from _python_assignment_fields(node)
    elif isinstance(node, ast.AnnAssign):
        yield from _python_annotated_field(node)
    elif isinstance(node, ast.Dict):
        yield from _python_dict_fields(node)
    elif isinstance(node, ast.Call):
        yield from _python_call_fields(node)
    elif isinstance(node, ast.NamedExpr):
        key = _python_target_key(node.target)
        if key is not None:
            yield key, node.value, node.lineno


def _iter_python_field_nodes(tree: ast.AST):
    for node in ast.walk(tree):
        yield from _python_fields_for_node(node)


def _python_ast_violations(path: str, text: str) -> list[Violation]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [Violation(path, "tracked validation Python is not syntactically valid")]
    violations: list[Violation] = []
    fields = list(_iter_python_field_nodes(tree))
    index = _python_scope_index(tree)
    constants_by_position = _python_constant_snapshots(
        tree,
        [value for _key, value, _line in fields],
        index,
    )
    for key, value_node, line in fields:
        key_domains = [match.group(0) for match in DOMAIN_RE.finditer(key)]
        if any(not _is_allowed_raw_domain(domain) for domain in key_domains):
            violations.append(Violation(path, "mapping key contains a non-reserved domain", line))
        normalized_key = _normalize_key(key)
        if normalized_key not in IDENTITY_FIELD_KEYS and not _is_tenant_identifier_key(normalized_key):
            continue
        scope = index.scope_by_node[value_node]
        constants = constants_by_position[(scope, value_node.lineno, value_node.col_offset)]
        value = _python_literal(value_node, constants)
        if value is _MISSING_LITERAL:
            continue
        for candidate in _literal_candidates(value):
            detail = _identity_violation_detail(normalized_key, candidate)
            if detail is not None:
                violations.append(Violation(path, detail, line))
                break
    return violations


def _candidate_skip_lines(lines: list[str]) -> set[int]:
    skip_level: int | None = None
    flagged: set[int] = set()
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        heading = HEADING_RE.fullmatch(stripped)
        if heading is not None:
            level = len(heading.group(1))
            title = heading.group(2).casefold()
            if title.startswith("skip"):
                skip_level = level
            elif skip_level is not None and level <= skip_level:
                skip_level = None
            continue
        if skip_level is not None and DOMAIN_RE.search(line):
            flagged.add(index)
    return flagged


def _path_violations(paths: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    for path in paths:
        folded = path.casefold()
        if folded.startswith(tuple(prefix.casefold() for prefix in PRIVATE_PREFIXES)):
            violations.append(Violation(path, "private validation corpus or run output is tracked"))
        if _is_root_domain_dump(path) or _is_root_scan_dump(path):
            violations.append(Violation(path, "root per-domain JSON dump is tracked"))
        if _has_target_path_component(path):
            violations.append(Violation(path, "validation artifact path contains a non-reserved domain"))
        if folded.startswith("validation/") and Path(path).suffix.casefold() not in SCAN_SUFFIXES:
            violations.append(Violation(path, "validation artifact extension is not approved"))
    return violations


def _has_unsafe_target_field(line: str, *, python_source: bool = False) -> bool:
    pattern = PY_TARGET_FIELD_RE if python_source else TARGET_FIELD_RE
    value_group = 2 if python_source else 1
    return any(not _is_allowed_domain(match.group(value_group)) for match in pattern.finditer(line))


def _has_unsafe_recon_command(line: str) -> bool:
    return any(not _is_allowed_domain(match.group(1)) for match in RECON_COMMAND_RE.finditer(line))


def _has_unsafe_dns_owner(line: str) -> bool:
    return any(not _is_allowed_raw_domain(match.group(1)) for match in DNS_OWNER_ARROW_RE.finditer(line))


def _prose_identity_violation(line: str, *, python_source: bool = False) -> str | None:
    display_pattern = PY_DISPLAY_VALUE_RE if python_source else PROSE_DISPLAY_VALUE_RE
    organization_pattern = PY_ORGANIZATION_VALUE_RE if python_source else PROSE_ORGANIZATION_VALUE_RE
    value_group = 2 if python_source else 1
    for match in display_pattern.finditer(line):
        value = match.group(value_group).strip()
        if value.casefold() not in {"none", "null"} and DISPLAY_NAME_RE.fullmatch(value) is None:
            return "display_name is not a constrained synthetic sentinel"
    for match in organization_pattern.finditer(line):
        if match.group(value_group).strip().casefold() not in {"none", "null", "redacted"}:
            return "organization field retains nonpublishable identity detail"
    return None


def _prose_field_violation(line: str) -> str | None:
    stripped = line.strip()
    if stripped.startswith("|") and stripped.endswith("|"):
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 2:
            return None
        candidate = f"{cells[0]}: {cells[1]}"
    else:
        candidate = line
    candidate = candidate.replace("**", "").replace("__", "")
    match = PROSE_IDENTITY_FIELD_RE.fullmatch(candidate)
    if match is None:
        return None
    raw_key = match.group(1)
    normalized_key = _normalize_key(raw_key)
    if normalized_key not in IDENTITY_FIELD_KEYS and not _is_tenant_identifier_key(normalized_key):
        return None
    value_text = match.group(2).strip()
    try:
        value = ast.literal_eval(value_text.rstrip(","))
    except (ValueError, SyntaxError):
        quoted = re.match(r"^([\"'`])(.+?)\1(?:\s*[,;].*)?$", value_text)
        value = quoted.group(2) if quoted is not None else value_text.strip("`\"'")
    return _identity_violation_detail(normalized_key, value)


def _continued_identity_violation(key: str, line: str) -> str | None:
    value = MARKDOWN_PREFIX_RE.sub("", line, count=1).strip().strip("`\"'")
    return _identity_violation_detail(_normalize_key(key), value)


def _command_continuation_marker(line: str) -> str | None:
    stripped = line.rstrip()
    if len(stripped) >= 2 and stripped[-1] in {"\\", "`", "^"} and stripped[-2].isspace():
        return stripped[-1]
    return None


def _continued_recon_commands(lines: list[str]):
    start: int | None = None
    parts: list[str] = []
    for index, line in enumerate(lines, start=1):
        if start is None:
            marker = _command_continuation_marker(line)
            if marker is None or RECON_COMMAND_PREFIX_RE.search(line) is None:
                continue
            start = index
            parts = [line.rstrip()[:-1]]
            continue
        marker = _command_continuation_marker(line)
        parts.append(line.rstrip()[:-1] if marker is not None else line)
        if marker is None:
            yield start, " ".join(part.strip() for part in parts)
            start = None
            parts = []
    if start is not None:
        yield start, " ".join(part.strip() for part in parts)


def _markdown_table_cells(line: str) -> list[str] | None:
    stripped = line.strip()
    if not (stripped.startswith("|") and stripped.endswith("|")):
        return None
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _is_markdown_separator_row(cells: list[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell) is not None for cell in cells)


def _dns_record_value_is_safe(value: str) -> bool:
    return _is_disclosure_safe_raw_value(value.strip().strip("`\"'"))


def _dns_table_violations(path: str, lines: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    columns: tuple[int, int, int] | None = None
    for index, line in enumerate(lines, start=1):
        cells = _markdown_table_cells(line)
        if cells is None:
            columns = None
            continue
        normalized = [_normalize_key(cell.strip("`*_")) for cell in cells]
        owner_index = next((i for i, key in enumerate(normalized) if key in {"owner", "name"}), None)
        type_index = next((i for i, key in enumerate(normalized) if key in {"record_type", "type"}), None)
        value_index = next((i for i, key in enumerate(normalized) if key in {"rdata", "record_value", "value"}), None)
        if owner_index is not None and type_index is not None and value_index is not None:
            columns = (owner_index, type_index, value_index)
            continue
        if columns is None or _is_markdown_separator_row(cells):
            continue
        owner_index, type_index, value_index = columns
        if max(columns) >= len(cells):
            violations.append(Violation(path, "DNS record table row has an invalid shape", index))
            continue
        owner = cells[owner_index].strip().strip("`\"'").rstrip(".")
        record_type = cells[type_index].strip().upper()
        value = cells[value_index]
        if owner not in {"@", "apex", "root"} and (
            PATH_DOMAIN_RE.fullmatch(owner) is None or not _is_allowed_domain(owner)
        ):
            violations.append(Violation(path, "DNS record owner is not reserved or synthetic", index))
        if record_type in {"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"} and not _dns_record_value_is_safe(
            value
        ):
            violations.append(Violation(path, "DNS record value is outside the disclosure-safe grammar", index))
    return violations


def _dns_row_violations(path: str, lines: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    for index, line in enumerate(lines, start=1):
        match = DNS_RECORD_ROW_RE.fullmatch(line)
        if match is not None:
            if not _is_allowed_domain(match.group(1)):
                violations.append(Violation(path, "DNS record owner is not reserved or synthetic", index))
            if not _dns_record_value_is_safe(match.group(3)):
                violations.append(Violation(path, "DNS record value is outside the disclosure-safe grammar", index))
            continue
        ownerless = OWNERLESS_TXT_ROW_RE.fullmatch(line)
        if ownerless is not None and not _dns_record_value_is_safe(ownerless.group(1)):
            violations.append(Violation(path, "DNS record value is outside the disclosure-safe grammar", index))
    return violations


def _continued_command_violations(path: str, lines: list[str]) -> list[Violation]:
    return [
        Violation(path, "recon example uses a non-reserved domain", line)
        for line, command in _continued_recon_commands(lines)
        if _has_unsafe_recon_command(command)
    ]


@dataclass(frozen=True)
class _LineScanContext:
    candidate_skip_lines: set[int]
    scan_line_identity: bool
    scan_exact_lines: bool
    python_source: bool


def _single_line_violations(
    path: str,
    line: str,
    index: int,
    context: _LineScanContext,
) -> list[Violation]:
    violations = [
        Violation(path, detail, index)
        for detail in _sensitive_value_violations(line, python_source=context.python_source)
    ]
    unsafe_target_field = context.scan_line_identity and _has_unsafe_target_field(
        line,
        python_source=context.python_source,
    )
    if unsafe_target_field:
        violations.append(Violation(path, "target-domain field is not reserved or synthetic", index))
    if _has_unsafe_recon_command(line):
        violations.append(Violation(path, "recon example uses a non-reserved domain", index))
    if context.scan_line_identity and _has_unsafe_dns_owner(line):
        violations.append(Violation(path, "DNS example owner is not reserved or synthetic", index))
    prose_detail = (
        _prose_identity_violation(line, python_source=context.python_source) if context.scan_line_identity else None
    )
    if prose_detail is not None:
        violations.append(Violation(path, prose_detail, index))
    field_detail = (
        _prose_field_violation(line)
        if context.scan_line_identity and not context.python_source and not unsafe_target_field
        else None
    )
    if field_detail is not None:
        violations.append(Violation(path, field_detail, index))
    domain_line = _looks_like_domain_line(line) if context.scan_exact_lines else None
    if domain_line is not None and not _is_allowed_domain(domain_line):
        violations.append(Violation(path, "corpus line is not reserved or synthetic", index))
    if index in context.candidate_skip_lines:
        violations.append(Violation(path, "candidate SKIP detail retains a domain-shaped value", index))
    return violations


def _identity_continuation(line: str, *, python_source: bool) -> re.Match[str] | None:
    if python_source:
        return None
    continuation_line = line.replace("**", "").replace("__", "")
    return CONTINUED_IDENTITY_FIELD_RE.fullmatch(continuation_line)


def _line_violations(path: str, lines: list[str], suffix: str) -> list[Violation]:
    violations = [
        *_dns_table_violations(path, lines),
        *_dns_row_violations(path, lines),
        *_continued_command_violations(path, lines),
    ]
    context = _LineScanContext(
        candidate_skip_lines=_candidate_skip_lines(lines) if suffix == ".md" else set(),
        scan_line_identity=suffix not in STRUCTURED_SUFFIXES | {".csv"},
        scan_exact_lines=suffix == ".txt",
        python_source=suffix == ".py",
    )
    pending_identity_key: str | None = None
    for index, line in enumerate(lines, start=1):
        continuation = _identity_continuation(line, python_source=context.python_source)
        if pending_identity_key is not None and line.strip() and continuation is None:
            detail = _continued_identity_violation(pending_identity_key, line)
            if detail is not None:
                violations.append(Violation(path, detail, index))
            if (
                _normalize_key(pending_identity_key) not in DOMAIN_LIST_KEYS
                or MARKDOWN_LIST_ITEM_RE.match(line) is None
            ):
                pending_identity_key = None
        violations.extend(_single_line_violations(path, line, index, context))
        if continuation is not None:
            candidate_key = continuation.group(1)
            normalized_key = _normalize_key(candidate_key)
            if normalized_key in IDENTITY_FIELD_KEYS or _is_tenant_identifier_key(normalized_key):
                pending_identity_key = candidate_key
    return violations


def _file_content_violations(root: Path, path: str) -> list[Violation]:
    full_path = root / path
    if full_path.is_symlink():
        return [Violation(path, "validation artifact must not be a symbolic link")]
    if not full_path.exists():
        return []
    try:
        lines = full_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return [Violation(path, "validation artifact is not valid UTF-8")]
    suffix = Path(path).suffix.lower()
    violations: list[Violation] = []
    if suffix in STRUCTURED_SUFFIXES:
        violations.extend(_structured_violations(path, lines))
    elif suffix == ".csv":
        violations.extend(_csv_violations(path, lines))
    elif suffix == ".py":
        violations.extend(_python_ast_violations(path, "\n".join(lines)))
    violations.extend(_line_violations(path, lines, suffix))
    return violations


def _content_violations(root: Path, paths: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    for path in paths:
        if _should_scan_content(path):
            violations.extend(_file_content_violations(root, path))
    return violations


def _retired_target_example_violations(root: Path, paths: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    for path in paths:
        if _has_retired_target_example(path):
            violations.append(Violation(path, "retired target-example identity is tracked"))
        full_path = root / path
        if full_path.is_symlink() or not full_path.is_file():
            continue
        try:
            content = full_path.read_bytes()
        except OSError:
            continue
        if b"\0" in content:
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for line, value in enumerate(text.splitlines(), start=1):
            if _has_retired_target_example(value):
                violations.append(Violation(path, "retired target-example identity is tracked", line))
    return violations


def _deduplicate(violations: list[Violation]) -> list[Violation]:
    seen: set[tuple[str, str, int | None]] = set()
    unique: list[Violation] = []
    for violation in violations:
        key = (violation.path, violation.detail, violation.line)
        if key not in seen:
            seen.add(key)
            unique.append(violation)
    return unique


def find_violations(root: Path = ROOT, paths: list[str] | None = None) -> list[Violation]:
    tracked = paths if paths is not None else _tracked_files(root)
    normalized = [path.replace("\\", "/") for path in tracked]
    return _deduplicate(
        [
            *_path_violations(normalized),
            *_content_violations(root, normalized),
            *_retired_target_example_violations(root, normalized),
        ]
    )


def main() -> int:
    violations = find_violations()
    if violations:
        print("Validation hygiene failed:")
        for violation in violations:
            print(f"  {violation.render()}")
        print("")
        print("Keep real apexes, per-domain outputs, and private run artifacts local.")
        print("Commit only synthetic examples or aggregate validation statistics.")
        return 1
    print("OK: configured validation hygiene checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
