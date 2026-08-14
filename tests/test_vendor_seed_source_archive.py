"""Tests for bounded, private vendor-seed provider-source acquisition."""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from validation import archive_vendor_seed_sources


class _Stream(httpx.AsyncByteStream):
    def __init__(self, content: bytes) -> None:
        self._content = content

    async def __aiter__(self) -> AsyncGenerator[bytes]:
        if self._content:
            yield self._content

    async def aclose(self) -> None:
        return None


def _plan(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    value = {
        "schema_version": 1,
        "private": True,
        "source_set_id": "vendor-seed-sources-2026-08",
        "purpose": (
            "Archive exact provider-controlled customer evidence before the disjoint vendor-seed frame is frozen."
        ),
        "providers": [
            {
                "slug": "shopify",
                "allowed_domains": ["shopify.com"],
                "sources": [
                    {
                        "id": "customer-evidence",
                        "url": "https://www.shopify.com/case-studies",
                        "expected_media_type": "text/html",
                    }
                ],
            },
            {
                "slug": "webflow",
                "allowed_domains": ["webflow.com"],
                "sources": [
                    {
                        "id": "customer-evidence",
                        "url": "https://webflow.com/customers",
                        "expected_media_type": "text/html",
                    }
                ],
            },
        ],
    }
    path = tmp_path / "source-plan.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _client(
    handler: Any,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_archiver_writes_immutable_receipt_and_exact_archives(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = b"shopify-source" if "shopify" in str(request.url) else b"webflow-source"
        return httpx.Response(200, headers={"Content-Type": "text/html; charset=utf-8"}, stream=_Stream(body))

    output = tmp_path / "frozen-sources"
    async with _client(respond) as client:
        receipt = await archive_vendor_seed_sources.archive_vendor_seed_sources(
            _plan(tmp_path),
            output,
            client=client,
            retrieved_at="2026-08-13T12:00:00Z",
        )

    assert len(requests) == 2
    assert all(request.method == "GET" for request in requests)
    assert all(request.headers["accept-encoding"] == "identity" for request in requests)
    assert receipt["totals"] == {
        "provider_count": 2,
        "source_count": 2,
        "archive_bytes": len(b"shopify-source") + len(b"webflow-source"),
        "selected_target_requests": 0,
    }
    assert (output / "archives" / "shopify" / "customer-evidence.html").read_bytes() == b"shopify-source"
    assert (output / "archives" / "webflow" / "customer-evidence.html").read_bytes() == b"webflow-source"
    assert (output / "source-plan.json").read_bytes() == (tmp_path / "source-plan.json").read_bytes()
    loaded, raw = archive_vendor_seed_sources.load_source_receipt(output / "receipt.json")
    assert loaded == receipt
    assert raw.endswith(b"\n")
    assert len(cast(str, loaded["receipt_digest_sha256"])) == 64


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "headers", "content", "message"),
    [
        (302, {"Content-Type": "text/html", "Location": "https://webflow.com/new"}, b"move", "HTTP 302"),
        (200, {"Content-Type": "application/pdf"}, b"pdf", "unexpected media type"),
        (200, {"Content-Type": "text/html", "Content-Encoding": "gzip"}, b"gzip", "compressed content"),
        (200, {"Content-Type": "text/html", "Content-Length": "invalid"}, b"body", "invalid length"),
        (200, {"Content-Type": "text/html", "Content-Length": "99"}, b"body", "declared length"),
        (200, {"Content-Type": "text/html"}, b"", "empty response"),
    ],
)
async def test_archiver_fails_closed_without_partial_output(
    tmp_path: Path,
    status: int,
    headers: dict[str, str],
    content: bytes,
    message: str,
) -> None:
    output = tmp_path / "frozen-sources"

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers, stream=_Stream(content), request=request)

    async with _client(respond) as client:
        with pytest.raises(ValueError, match=message):
            await archive_vendor_seed_sources.archive_vendor_seed_sources(
                _plan(tmp_path),
                output,
                client=client,
                retrieved_at="2026-08-13T12:00:00Z",
            )
    assert not output.exists()


@pytest.mark.asyncio
async def test_archiver_bounds_streamed_body_and_total(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive_vendor_seed_sources, "MAX_SOURCE_BYTES", 8)

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "text/html"}, stream=_Stream(b"123456789"), request=request)

    output = tmp_path / "frozen-sources"
    async with _client(respond) as client:
        with pytest.raises(ValueError, match="response-size limit"):
            await archive_vendor_seed_sources.archive_vendor_seed_sources(
                _plan(tmp_path),
                output,
                client=client,
                retrieved_at="2026-08-13T12:00:00Z",
            )
    assert not output.exists()


@pytest.mark.asyncio
async def test_archiver_rejects_unsafe_or_unowned_destination_before_request(tmp_path: Path) -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers={"Content-Type": "text/html"}, stream=_Stream(b"unused"), request=request)

    plan_path = _plan(tmp_path)
    plan = cast(dict[str, Any], json.loads(plan_path.read_text(encoding="utf-8")))
    plan["providers"][0]["sources"][0]["url"] = "https://127.0.0.1/private"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    async with _client(respond) as client:
        with pytest.raises(ValueError, match="public provider host"):
            await archive_vendor_seed_sources.archive_vendor_seed_sources(
                plan_path,
                tmp_path / "unsafe-output",
                client=client,
            )
    assert calls == 0

    plan_path = _plan(tmp_path / "unowned")
    plan = cast(dict[str, Any], json.loads(plan_path.read_text(encoding="utf-8")))
    plan["providers"][0]["sources"][0]["url"] = "https://webflow.com/customers"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    async with _client(respond) as client:
        with pytest.raises(ValueError, match="outside the declared provider domains"):
            await archive_vendor_seed_sources.archive_vendor_seed_sources(
                plan_path,
                tmp_path / "unowned-output",
                client=client,
            )
    assert calls == 0


@pytest.mark.asyncio
async def test_archiver_refuses_existing_output_before_network(tmp_path: Path) -> None:
    output = tmp_path / "frozen-sources"
    output.mkdir()
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers={"Content-Type": "text/html"}, stream=_Stream(b"unused"), request=request)

    async with _client(respond) as client:
        with pytest.raises(ValueError, match="already exists"):
            await archive_vendor_seed_sources.archive_vendor_seed_sources(_plan(tmp_path), output, client=client)
    assert calls == 0


@pytest.mark.asyncio
async def test_receipt_tamper_is_rejected(tmp_path: Path) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "text/html"}, stream=_Stream(b"source"), request=request)

    output = tmp_path / "frozen-sources"
    async with _client(respond) as client:
        await archive_vendor_seed_sources.archive_vendor_seed_sources(
            _plan(tmp_path),
            output,
            client=client,
            retrieved_at="2026-08-13T12:00:00Z",
        )
    receipt_path = output / "receipt.json"
    receipt = cast(dict[str, Any], json.loads(receipt_path.read_text(encoding="utf-8")))
    receipt["totals"]["archive_bytes"] += 1
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(ValueError, match="totals do not match"):
        archive_vendor_seed_sources.load_source_receipt(receipt_path)


def test_cli_error_does_not_echo_private_source_identifiers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def fail(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise ValueError("provider source request 1 failed")

    monkeypatch.setattr(archive_vendor_seed_sources, "archive_vendor_seed_sources", fail)
    plan_path = tmp_path / "private-provider-name.example.json"
    assert archive_vendor_seed_sources.main(["--plan", str(plan_path), "--output-dir", str(tmp_path / "out")]) == 2
    output = capsys.readouterr()
    assert "private-provider-name" not in output.err
    assert output.err.strip() == "error: provider source request 1 failed"


def test_cli_success_prints_only_safe_counts_and_commitments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def succeed(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "totals": {
                "provider_count": 2,
                "source_count": 4,
                "archive_bytes": 512,
                "selected_target_requests": 0,
            },
            "plan_digest_sha256": "1" * 64,
            "receipt_digest_sha256": "2" * 64,
        }

    monkeypatch.setattr(archive_vendor_seed_sources, "archive_vendor_seed_sources", succeed)
    plan_path = tmp_path / "private-customer-name.example.json"
    assert archive_vendor_seed_sources.main(["--plan", str(plan_path), "--output-dir", str(tmp_path / "out")]) == 0
    rendered = capsys.readouterr().out
    summary = json.loads(rendered)
    assert summary["identifiers_printed"] == 0
    assert summary["selected_target_requests"] == 0
    assert summary["provider_count"] == 2
    assert "private-customer-name" not in rendered
