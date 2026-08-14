"""Archive a bounded provider-controlled source set for vendor-seed work.

The private plan declares existing catalog providers, provider-controlled
registrable domains, exact HTTPS source URLs, and expected media types. This
tool downloads those pages sequentially with no redirects, credentials,
compression, retries, or selected-namespace requests. It writes an immutable
private receipt and prints only counts and cryptographic commitments.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, cast
from urllib.parse import urlsplit

import httpx

from recon_tool.fingerprints import load_builtin_fingerprints
from recon_tool.http import http_client
from recon_tool.sources.dns_tables import is_public_dns_name
from recon_tool.validator import validate_domain
from validation.prepare_catalog_round import REPO_ROOT
from validation.ranked_sampling import bounded_stable_read
from validation.run_path_safety import validate_private_output_root

PRIVATE_ROOTS = (
    REPO_ROOT / "validation" / "corpus-private",
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "local",
)
SCHEMA_VERSION = 1
MAX_PLAN_BYTES = 512 * 1024
MAX_PROVIDERS = 25
MAX_SOURCES_PER_PROVIDER = 100
MAX_SOURCE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 20.0
ALLOWED_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/pdf",
        "application/xhtml+xml",
        "text/html",
        "text/plain",
    }
)
_MEDIA_EXTENSIONS = {
    "application/json": "json",
    "application/pdf": "pdf",
    "application/xhtml+xml": "xhtml",
    "text/html": "html",
    "text/plain": "txt",
}
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,79}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PLAN_KEYS = frozenset({"schema_version", "private", "source_set_id", "purpose", "providers"})
_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "private",
        "source_set_id",
        "purpose",
        "retrieved_at",
        "plan_digest_sha256",
        "implementation_digest_sha256",
        "acquisition_policy",
        "providers",
        "totals",
        "receipt_digest_sha256",
    }
)


@dataclass(slots=True)
class _PlanState:
    catalog_slugs: frozenset[str]
    slugs: set[str]
    domains: set[str]
    urls: set[str]


@dataclass(slots=True)
class _ReceiptProviderContext:
    provider_index: int
    slug: str
    domains: frozenset[str]
    retrieved_at: object
    seen_ids: set[str]
    seen_urls: set[str]


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            _fail(f"source plan or receipt contains duplicate field: {key}")
        value[key] = child
    return value


def _strict_object(value: object, *, name: str, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{name} must be an object")
    actual = frozenset(value)
    missing = sorted(keys - actual)
    extra = sorted(actual - keys)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        _fail(f"{name} has invalid fields: {'; '.join(details)}")
    return value


def _identifier(value: object, *, name: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _fail(f"{name} must be a lowercase identifier")
    return value


def _text(value: object, *, name: str, minimum: int) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a string")
    normalized = " ".join(value.split())
    if len(normalized) < minimum or normalized.casefold() in {"n/a", "none", "tbd", "unknown", "latest"}:
        _fail(f"{name} must be meaningful and at least {minimum} characters")
    return normalized


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def _utc_timestamp(value: str | None = None) -> str:
    if value is None:
        return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("retrieved_at must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        _fail("retrieved_at must carry the UTC timezone")
    return value


def _private_file(path: Path, *, kind: str) -> Path:
    resolved = path.resolve(strict=False)
    validate_private_output_root(resolved.parent, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    if resolved.name in {"", ".", ".."}:
        _fail(f"{kind} must name a file")
    return resolved


def _private_directory(path: Path) -> Path:
    resolved = path.resolve(strict=False)
    validate_private_output_root(resolved, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    return resolved


def _read_json(path: Path, *, maximum_bytes: int, kind: str) -> tuple[dict[str, object], bytes]:
    raw = bounded_stable_read(path, maximum_bytes=maximum_bytes, kind=kind)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{kind} must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        _fail(f"{kind} must be an object")
    return value, raw


def _provider_domain(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value.isascii() or value != value.strip().lower():
        _fail(f"{name} must be a lowercase ASCII registrable domain")
    if not is_public_dns_name(value):
        _fail(f"{name} must be a public DNS name")
    try:
        normalized = validate_domain(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid registrable domain") from exc
    if normalized != value:
        _fail(f"{name} must be a registrable apex, not a subdomain")
    return value


def _source_url(value: object, *, allowed_domains: frozenset[str], name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or value != value.strip()
        or len(value) > 2048
        or any(ord(character) < 32 for character in value)
    ):
        _fail(f"{name} must be a bounded ASCII URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{name} is malformed") from exc
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username
        or parsed.password
        or port not in {None, 443}
        or parsed.fragment
        or not is_public_dns_name(host)
    ):
        _fail(f"{name} must use HTTPS on a public provider host without credentials or a fragment")
    try:
        apex = validate_domain(host)
    except ValueError as exc:
        raise ValueError(f"{name} has an invalid host") from exc
    if apex not in allowed_domains:
        _fail(f"{name} host is outside the declared provider domains")
    return value


def _media_type(value: object, *, name: str) -> str:
    if not isinstance(value, str) or value not in ALLOWED_MEDIA_TYPES:
        _fail(f"{name} must be one of {', '.join(sorted(ALLOWED_MEDIA_TYPES))}")
    return value


def _catalog_slugs() -> frozenset[str]:
    return frozenset(fingerprint.slug for fingerprint in load_builtin_fingerprints())


def _normalize_provider_domains(raw: object, *, provider_index: int, state: _PlanState) -> list[str]:
    if not isinstance(raw, list) or not raw or len(raw) > 20:
        _fail("each provider must declare between 1 and 20 provider domains")
    domains: list[str] = []
    for domain_index, raw_domain in enumerate(raw):
        domain = _provider_domain(
            raw_domain,
            name=f"providers[{provider_index}].allowed_domains[{domain_index}]",
        )
        if domain in domains:
            _fail("provider domains must be unique within a provider")
        if domain in state.domains:
            _fail("one provider domain cannot be assigned to multiple providers")
        domains.append(domain)
        state.domains.add(domain)
    return domains


def _normalize_provider_sources(
    raw: object,
    *,
    provider_index: int,
    allowed_domains: frozenset[str],
    state: _PlanState,
) -> list[dict[str, str]]:
    if not isinstance(raw, list) or not raw or len(raw) > MAX_SOURCES_PER_PROVIDER:
        _fail(f"each provider must contain between 1 and {MAX_SOURCES_PER_PROVIDER} sources")
    sources: list[dict[str, str]] = []
    seen_source_ids: set[str] = set()
    for source_index, raw_source in enumerate(raw):
        source = _strict_object(
            raw_source,
            name=f"providers[{provider_index}].sources[{source_index}]",
            keys=frozenset({"id", "url", "expected_media_type"}),
        )
        source_id = _identifier(
            source["id"],
            name=f"providers[{provider_index}].sources[{source_index}].id",
        )
        if source_id in seen_source_ids:
            _fail("source IDs must be unique within a provider")
        seen_source_ids.add(source_id)
        url = _source_url(
            source["url"],
            allowed_domains=allowed_domains,
            name=f"providers[{provider_index}].sources[{source_index}].url",
        )
        if url in state.urls:
            _fail("source URLs must be unique across the source set")
        state.urls.add(url)
        sources.append(
            {
                "id": source_id,
                "url": url,
                "expected_media_type": _media_type(
                    source["expected_media_type"],
                    name=f"providers[{provider_index}].sources[{source_index}].expected_media_type",
                ),
            }
        )
    return sources


def _normalize_provider(raw: object, *, provider_index: int, state: _PlanState) -> dict[str, object]:
    provider = _strict_object(
        raw,
        name=f"providers[{provider_index}]",
        keys=frozenset({"slug", "allowed_domains", "sources"}),
    )
    slug = _identifier(provider["slug"], name=f"providers[{provider_index}].slug")
    if slug not in state.catalog_slugs:
        _fail("provider slug is absent from the current catalog")
    if slug in state.slugs:
        _fail("provider slugs must be unique")
    state.slugs.add(slug)
    domains = _normalize_provider_domains(provider["allowed_domains"], provider_index=provider_index, state=state)
    sources = _normalize_provider_sources(
        provider["sources"],
        provider_index=provider_index,
        allowed_domains=frozenset(domains),
        state=state,
    )
    return {
        "slug": slug,
        "allowed_domains": sorted(domains),
        "sources": sorted(sources, key=lambda row: row["id"]),
    }


def _normalize_plan(value: object) -> dict[str, object]:
    plan = _strict_object(value, name="source plan", keys=_PLAN_KEYS)
    if plan["schema_version"] != SCHEMA_VERSION or plan["private"] is not True:
        _fail(f"source plan must use private schema version {SCHEMA_VERSION}")
    source_set_id = _identifier(plan["source_set_id"], name="source_set_id")
    purpose = _text(plan["purpose"], name="purpose", minimum=30)
    raw_providers = plan["providers"]
    if not isinstance(raw_providers, list) or not raw_providers or len(raw_providers) > MAX_PROVIDERS:
        _fail(f"providers must contain between 1 and {MAX_PROVIDERS} entries")
    state = _PlanState(catalog_slugs=_catalog_slugs(), slugs=set(), domains=set(), urls=set())
    providers = [
        _normalize_provider(raw_provider, provider_index=provider_index, state=state)
        for provider_index, raw_provider in enumerate(raw_providers)
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "source_set_id": source_set_id,
        "purpose": purpose,
        "providers": sorted(providers, key=lambda row: cast(str, row["slug"])),
    }


def _implementation_digest() -> str:
    paths = (
        Path(__file__).resolve(),
        REPO_ROOT / "src" / "recon_tool" / "fingerprint_artifact.py",
        REPO_ROOT / "src" / "recon_tool" / "fingerprints.py",
        REPO_ROOT / "src" / "recon_tool" / "http.py",
        REPO_ROOT / "src" / "recon_tool" / "psl.py",
        REPO_ROOT / "src" / "recon_tool" / "sources" / "dns_tables.py",
        REPO_ROOT / "src" / "recon_tool" / "validator.py",
        REPO_ROOT / "src" / "recon_tool" / "data" / "fingerprints.generated.json",
        REPO_ROOT / "pyproject.toml",
        REPO_ROOT / "uv.lock",
    )
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(REPO_ROOT).as_posix().encode("utf-8")
        raw = bounded_stable_read(path, maximum_bytes=32 * 1024 * 1024, kind="source freezer implementation")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _acquisition_policy() -> dict[str, object]:
    return {
        "network_scope": "provider-controlled source pages only; selected namespaces are not requested",
        "method": "GET",
        "redirects": False,
        "credentials": False,
        "retries": 0,
        "accept_encoding": "identity",
        "allowed_media_types": sorted(ALLOWED_MEDIA_TYPES),
        "maximum_source_bytes": MAX_SOURCE_BYTES,
        "maximum_total_bytes": MAX_TOTAL_BYTES,
        "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
    }


async def _fetch_source(
    client: httpx.AsyncClient,
    *,
    url: str,
    expected_media_type: str,
    request_number: int,
) -> bytes:
    try:
        async with client.stream(
            "GET",
            url,
            follow_redirects=False,
            headers={
                "Accept": expected_media_type,
                "Accept-Encoding": "identity",
            },
        ) as response:
            declared_length = _validate_response_headers(response, expected_media_type, request_number)
            raw = await _read_response_body(response, request_number)
            if declared_length is not None and len(raw) != declared_length:
                _fail(f"provider source request {request_number} body does not match its declared length")
    except ValueError:
        raise
    except (httpx.HTTPError, OSError) as exc:
        raise ValueError(f"provider source request {request_number} failed") from exc
    if not raw:
        _fail(f"provider source request {request_number} returned an empty response")
    return raw


def _validate_response_headers(
    response: httpx.Response,
    expected_media_type: str,
    request_number: int,
) -> int | None:
    if response.status_code != 200:
        _fail(f"provider source request {request_number} returned HTTP {response.status_code}")
    encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in {"", "identity"}:
        _fail(f"provider source request {request_number} returned compressed content")
    observed_media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if observed_media_type != expected_media_type:
        _fail(f"provider source request {request_number} returned an unexpected media type")
    content_length = response.headers.get("content-length")
    if content_length is None:
        return None
    try:
        declared_length = int(content_length)
    except ValueError as exc:
        raise ValueError(f"provider source request {request_number} returned an invalid length") from exc
    if declared_length <= 0 or declared_length > MAX_SOURCE_BYTES:
        _fail(f"provider source request {request_number} declared an invalid response size")
    return declared_length


async def _read_response_body(response: httpx.Response, request_number: int) -> bytes:
    if response.is_stream_consumed:
        raw = response.content
        if len(raw) > MAX_SOURCE_BYTES:
            _fail(f"provider source request {request_number} exceeded the response-size limit")
        return raw
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_raw():
        total += len(chunk)
        if total > MAX_SOURCE_BYTES:
            _fail(f"provider source request {request_number} exceeded the response-size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _receipt_digest(receipt: Mapping[str, object]) -> str:
    digest_input = {key: value for key, value in receipt.items() if key != "receipt_digest_sha256"}
    return _digest(_canonical_json(digest_input))


def _validate_receipt_source(
    raw_source: object,
    *,
    source_index: int,
    context: _ReceiptProviderContext,
) -> int:
    source = _strict_object(
        raw_source,
        name=f"source receipt providers[{context.provider_index}].sources[{source_index}]",
        keys=frozenset(
            {
                "id",
                "url",
                "retrieved_at",
                "media_type",
                "archive",
                "archive_bytes",
                "archive_digest_sha256",
            }
        ),
    )
    source_id = _identifier(source["id"], name="source receipt source id")
    if source_id in context.seen_ids:
        _fail("source receipt source IDs must be unique within a provider")
    context.seen_ids.add(source_id)
    url = _source_url(source["url"], allowed_domains=context.domains, name="source receipt source URL")
    if url in context.seen_urls:
        _fail("source receipt source URLs must be unique")
    context.seen_urls.add(url)
    media_type = _media_type(source["media_type"], name="source receipt media_type")
    expected_archive = f"archives/{context.slug}/{source_id}.{_MEDIA_EXTENSIONS[media_type]}"
    if source["archive"] != expected_archive:
        _fail("source receipt archive path does not match its provider, source ID, and media type")
    if source["retrieved_at"] != context.retrieved_at:
        _fail("source receipt timestamps must match")
    size = source["archive_bytes"]
    if not isinstance(size, int) or isinstance(size, bool) or size < 1 or size > MAX_SOURCE_BYTES:
        _fail("source receipt archive_bytes is outside the allowed range")
    archive_digest = source["archive_digest_sha256"]
    if not isinstance(archive_digest, str) or _SHA256_RE.fullmatch(archive_digest) is None:
        _fail("source receipt archive digest must be a lowercase SHA-256 digest")
    return size


def _validate_receipt_providers(receipt: Mapping[str, object]) -> tuple[list[object], int, int]:
    providers = receipt["providers"]
    if not isinstance(providers, list) or not providers:
        _fail("source receipt providers must be a non-empty list")
    source_count = 0
    archive_bytes = 0
    seen_slugs: set[str] = set()
    seen_urls: set[str] = set()
    for provider_index, raw_provider in enumerate(providers):
        provider = _strict_object(
            raw_provider,
            name=f"source receipt providers[{provider_index}]",
            keys=frozenset({"slug", "allowed_domains", "sources"}),
        )
        slug = _identifier(provider["slug"], name="source receipt provider slug")
        if slug in seen_slugs:
            _fail("source receipt provider slugs must be unique")
        seen_slugs.add(slug)
        raw_domains = provider["allowed_domains"]
        if not isinstance(raw_domains, list) or not raw_domains:
            _fail("source receipt provider domains must be a non-empty list")
        domains = frozenset(_provider_domain(domain, name="source receipt provider domain") for domain in raw_domains)
        if len(domains) != len(raw_domains):
            _fail("source receipt provider domains must be unique")
        raw_sources = provider["sources"]
        if not isinstance(raw_sources, list) or not raw_sources:
            _fail("source receipt provider sources must be a non-empty list")
        context = _ReceiptProviderContext(
            provider_index=provider_index,
            slug=slug,
            domains=domains,
            retrieved_at=receipt["retrieved_at"],
            seen_ids=set(),
            seen_urls=seen_urls,
        )
        for source_index, raw_source in enumerate(raw_sources):
            archive_bytes += _validate_receipt_source(
                raw_source,
                source_index=source_index,
                context=context,
            )
            source_count += 1
    return providers, source_count, archive_bytes


def load_source_receipt(path: Path) -> tuple[dict[str, object], bytes]:
    """Load and verify one private source receipt without reading page archives."""
    resolved = _private_file(path, kind="source receipt")
    value, raw = _read_json(resolved, maximum_bytes=MAX_PLAN_BYTES, kind="source receipt")
    receipt = _strict_object(value, name="source receipt", keys=_RECEIPT_KEYS)
    if receipt["schema_version"] != SCHEMA_VERSION or receipt["private"] is not True:
        _fail(f"source receipt must use private schema version {SCHEMA_VERSION}")
    _identifier(receipt["source_set_id"], name="source receipt source_set_id")
    _text(receipt["purpose"], name="source receipt purpose", minimum=30)
    if not isinstance(receipt["retrieved_at"], str):
        _fail("source receipt retrieved_at must be a string")
    _utc_timestamp(receipt["retrieved_at"])
    for field in ("plan_digest_sha256", "implementation_digest_sha256", "receipt_digest_sha256"):
        if not isinstance(receipt[field], str) or _SHA256_RE.fullmatch(cast(str, receipt[field])) is None:
            _fail(f"source receipt {field} must be a lowercase SHA-256 digest")
    plan_raw = bounded_stable_read(
        resolved.parent / "source-plan.json",
        maximum_bytes=MAX_PLAN_BYTES,
        kind="archived source plan",
    )
    if receipt["plan_digest_sha256"] != _digest(plan_raw):
        _fail("source receipt plan digest does not match the archived source plan")
    if receipt["implementation_digest_sha256"] != _implementation_digest():
        _fail("source receipt implementation digest does not match the current source freezer")
    if receipt["acquisition_policy"] != _acquisition_policy():
        _fail("source receipt acquisition policy does not match the current fail-closed contract")
    providers, source_count, archive_bytes = _validate_receipt_providers(receipt)
    totals = _strict_object(
        receipt["totals"],
        name="source receipt totals",
        keys=frozenset({"provider_count", "source_count", "archive_bytes", "selected_target_requests"}),
    )
    expected_totals = {
        "provider_count": len(providers),
        "source_count": source_count,
        "archive_bytes": archive_bytes,
        "selected_target_requests": 0,
    }
    if totals != expected_totals or archive_bytes > MAX_TOTAL_BYTES:
        _fail("source receipt totals do not match its provider sources")
    if receipt["receipt_digest_sha256"] != _receipt_digest(receipt):
        _fail("source receipt digest does not match its content")
    return receipt, raw


async def archive_vendor_seed_sources(
    plan_path: Path,
    output_dir: Path,
    *,
    client: httpx.AsyncClient | None = None,
    retrieved_at: str | None = None,
) -> dict[str, object]:
    """Download one strict source plan and exclusively write its private receipt."""
    resolved_plan = _private_file(plan_path, kind="source plan")
    root = _private_directory(output_dir)
    if root.exists():
        _fail("source archive output already exists; refusing to replace it")
    raw_value, plan_raw = _read_json(resolved_plan, maximum_bytes=MAX_PLAN_BYTES, kind="source plan")
    plan = _normalize_plan(raw_value)
    timestamp = _utc_timestamp(retrieved_at)
    source_total = sum(
        len(cast(list[object], provider["sources"])) for provider in cast(list[dict[str, object]], plan["providers"])
    )
    root.parent.mkdir(parents=True, exist_ok=True)
    validate_private_output_root(root.parent, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    receipt_providers: list[dict[str, object]] = []
    total_bytes = 0
    request_number = 0
    async with http_client(provided=client, timeout=REQUEST_TIMEOUT_SECONDS, retry_transient=False) as active_client:
        with tempfile.TemporaryDirectory(prefix=".vendor-source-staging-", dir=root.parent) as staging_value:
            staging = Path(staging_value)
            for provider in cast(list[dict[str, object]], plan["providers"]):
                slug = cast(str, provider["slug"])
                receipt_sources: list[dict[str, object]] = []
                archive_directory = staging / "archives" / slug
                archive_directory.mkdir(parents=True, exist_ok=False)
                for source in cast(list[dict[str, str]], provider["sources"]):
                    request_number += 1
                    media_type = source["expected_media_type"]
                    raw = await _fetch_source(
                        active_client,
                        url=source["url"],
                        expected_media_type=media_type,
                        request_number=request_number,
                    )
                    total_bytes += len(raw)
                    if total_bytes > MAX_TOTAL_BYTES:
                        _fail(f"provider source responses exceed the {MAX_TOTAL_BYTES}-byte aggregate limit")
                    relative = f"archives/{slug}/{source['id']}.{_MEDIA_EXTENSIONS[media_type]}"
                    archive_path = staging / relative
                    try:
                        with archive_path.open("xb") as stream:
                            stream.write(raw)
                    except OSError as exc:
                        raise ValueError("could not write a staged provider source archive") from exc
                    receipt_sources.append(
                        {
                            "id": source["id"],
                            "url": source["url"],
                            "retrieved_at": timestamp,
                            "media_type": media_type,
                            "archive": relative,
                            "archive_bytes": len(raw),
                            "archive_digest_sha256": _digest(raw),
                        }
                    )
                receipt_providers.append(
                    {
                        "slug": slug,
                        "allowed_domains": provider["allowed_domains"],
                        "sources": receipt_sources,
                    }
                )
            receipt: dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "private": True,
                "source_set_id": plan["source_set_id"],
                "purpose": plan["purpose"],
                "retrieved_at": timestamp,
                "plan_digest_sha256": _digest(plan_raw),
                "implementation_digest_sha256": _implementation_digest(),
                "acquisition_policy": _acquisition_policy(),
                "providers": receipt_providers,
                "totals": {
                    "provider_count": len(receipt_providers),
                    "source_count": source_total,
                    "archive_bytes": total_bytes,
                    "selected_target_requests": 0,
                },
            }
            receipt["receipt_digest_sha256"] = _receipt_digest(receipt)
            receipt_raw = json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            try:
                with (staging / "source-plan.json").open("xb") as stream:
                    stream.write(plan_raw)
                with (staging / "receipt.json").open("xb") as stream:
                    stream.write(receipt_raw)
                if root.exists():
                    _fail("source archive output appeared during collection; refusing to replace it")
                staging.rename(root)
            except OSError as exc:
                raise ValueError("could not publish the complete private source archive atomically") from exc
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path, help="Strict ignored private provider source plan.")
    parser.add_argument("--output-dir", required=True, type=Path, help="New ignored private source archive directory.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = asyncio.run(archive_vendor_seed_sources(args.plan, args.output_dir))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    totals = cast(dict[str, object], receipt["totals"])
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "provider_count": totals["provider_count"],
                "source_count": totals["source_count"],
                "archive_bytes": totals["archive_bytes"],
                "plan_digest_sha256": receipt["plan_digest_sha256"],
                "receipt_digest_sha256": receipt["receipt_digest_sha256"],
                "selected_target_requests": 0,
                "identifiers_printed": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
