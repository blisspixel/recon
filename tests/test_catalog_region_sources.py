"""Tests for the bounded official regional-source freezer."""

from __future__ import annotations

import hashlib
import itertools
import json
import string
import subprocess
import sys
import urllib.request
from email.message import Message
from pathlib import Path
from types import TracebackType
from typing import cast

import pytest

from validation import prepare_catalog_region_sources as source_freezer


class FakeResponse:
    """Minimal context-managed urllib response for deterministic tests."""

    def __init__(
        self,
        raw: bytes,
        url: str,
        *,
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
        declared_length: str | None = None,
    ) -> None:
        self._raw = raw
        self._url = url
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self.headers["Content-Length"] = declared_length or str(len(raw))

    def read(self, amount: int = -1) -> bytes:
        return self._raw if amount < 0 else self._raw[:amount]

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


def test_documented_module_entrypoint_loads_from_repository_root() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "validation.prepare_catalog_region_sources", "--help"],
        cwd=source_freezer.REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--output-directory" in result.stdout
    validation_readme = (source_freezer.REPO_ROOT / "validation" / "README.md").read_text(encoding="utf-8")
    assert "python -m validation.prepare_catalog_region_sources" in validation_readme
    assert "python validation/prepare_catalog_region_sources.py" not in validation_readme


class FakeOpener:
    """Serve exact frozen bodies for the two allowed source URLs."""

    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, float, str, str]] = []

    def __call__(self, request: urllib.request.Request, *, timeout: float) -> FakeResponse:
        self.calls.append(
            (
                request.full_url,
                timeout,
                request.get_header("Accept-encoding") or "",
                request.get_method(),
            )
        )
        return self.responses[request.full_url]


def _alpha2_codes() -> list[str]:
    return ["".join(pair) for pair in itertools.islice(itertools.product(string.ascii_uppercase, repeat=2), 205)]


def _iana_html(codes: list[str]) -> bytes:
    rows = [
        "<tr><th>Domain</th><th>Type</th><th>TLD Manager</th></tr>",
        *(
            f'<tr><td><span class="domain tld"><a>.{code.casefold()}</a></span></td>'
            f"<td>country-code</td><td>Fixture manager</td></tr>"
            for code in codes
        ),
        *(f"<tr><td>.fixture-{index}</td><td>generic</td><td>Fixture manager</td></tr>" for index in range(800)),
    ]
    return (f'<html><table id="{source_freezer.IANA_TABLE_ID}">' + "".join(rows) + "</table></html>").encode()


def _un_html(codes: list[str]) -> bytes:
    header = "<tr>" + "".join(f"<td>{cell}</td>" for cell in source_freezer.UN_M49_HEADER) + "</tr>"
    regions = list(source_freezer.CANONICAL_REGIONS.items())
    rows: list[str] = []
    for index, code in enumerate(codes):
        region_code, region_name = regions[index // 41]
        cells = (
            "001",
            "World",
            region_code,
            region_name,
            "",
            "",
            "",
            "",
            f"Fixture area {index}",
            f"{index:03d}",
            code,
            f"X{index:02d}",
            "",
            "",
            "",
        )
        rows.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in cells) + "</tr>")
    return (
        f'<html><table id="{source_freezer.UN_M49_TABLE_ID}">' + header + "".join(rows) + "</table></html>"
    ).encode()


def _opener() -> tuple[FakeOpener, bytes, bytes]:
    codes = _alpha2_codes()
    iana_raw = _iana_html(codes)
    un_raw = _un_html(codes)
    return (
        FakeOpener(
            {
                source_freezer.IANA_URL: FakeResponse(iana_raw, source_freezer.IANA_URL),
                source_freezer.UN_M49_URL: FakeResponse(un_raw, source_freezer.UN_M49_URL),
            }
        ),
        iana_raw,
        un_raw,
    )


def test_source_freeze_is_deterministic_bounded_and_path_private(tmp_path: Path) -> None:
    opener, iana_raw, un_raw = _opener()
    output = tmp_path / "private" / "sources"

    first_outputs, first_manifest = source_freezer.prepare_source_freeze(
        output,
        opener=opener,
        retrieved_at="2026-08-13T20:00:00Z",
    )
    second_outputs, second_manifest = source_freezer.prepare_source_freeze(
        output,
        opener=opener,
        retrieved_at="2026-08-13T20:00:00Z",
    )

    assert first_outputs == second_outputs
    assert first_manifest == second_manifest
    assert first_outputs[source_freezer.OUTPUT_NAMES["iana"]] == iana_raw
    assert first_outputs[source_freezer.OUTPUT_NAMES["un_m49"]] == un_raw
    assert first_manifest["mapping"]["rows"] == 205
    assert first_manifest["privacy"] == {
        "official_source_requests": 2,
        "target_namespace_requests": 0,
        "target_identifiers_printed": 0,
    }
    assert all(call[1:] == (30.0, "identity", "GET") for call in opener.calls)


def test_manifest_commits_raw_sources_mapping_implementation_and_itself(tmp_path: Path) -> None:
    opener, iana_raw, un_raw = _opener()
    outputs, manifest = source_freezer.prepare_source_freeze(
        tmp_path / "private" / "sources",
        opener=opener,
        retrieved_at="2026-08-13T20:00:00Z",
    )

    assert manifest["sources"]["iana"]["sha256"] == hashlib.sha256(iana_raw).hexdigest()
    assert manifest["sources"]["un_m49"]["sha256"] == hashlib.sha256(un_raw).hexdigest()
    mapping = outputs[source_freezer.OUTPUT_NAMES["mapping"]]
    assert manifest["mapping"]["sha256"] == hashlib.sha256(mapping).hexdigest()
    assert len(manifest["implementation"]["execution_sha256"]) == 64
    digest_payload = dict(manifest)
    supplied = digest_payload.pop("manifest_digest_sha256")
    assert supplied == hashlib.sha256(source_freezer._canonical_json(digest_payload)).hexdigest()


def test_public_summary_omits_private_paths_and_target_rows(tmp_path: Path) -> None:
    opener, _, _ = _opener()
    output = tmp_path / "private" / "sources"
    _, manifest = source_freezer.prepare_source_freeze(
        output,
        opener=opener,
        retrieved_at="2026-08-13T20:00:00Z",
    )

    summary = source_freezer.public_summary(manifest, written=False)
    serialized = json.dumps(summary, sort_keys=True)

    assert str(output) not in serialized
    assert "private_file" not in serialized
    assert "Fixture area" not in serialized
    assert summary["privacy"]["private_artifacts_written"] is False
    assert summary["mapping"]["region_rows"] == [
        {"code": code, "name": name, "rows": 41} for code, name in source_freezer.CANONICAL_REGIONS.items()
    ]


def test_write_is_exclusive_and_second_attempt_makes_no_request(tmp_path: Path) -> None:
    opener, _, _ = _opener()
    output = tmp_path / "private" / "sources"

    manifest = source_freezer.write_source_freeze(
        output,
        opener=opener,
        retrieved_at="2026-08-13T20:00:00Z",
    )

    assert manifest["mapping"]["rows"] == 205
    assert {path.name for path in output.iterdir()} == set(source_freezer.OUTPUT_NAMES.values())
    assert all(path.stat().st_size > 0 for path in output.iterdir())
    calls_before = len(opener.calls)
    with pytest.raises(ValueError, match="refusing to replace"):
        source_freezer.write_source_freeze(output, opener=opener)
    assert len(opener.calls) == calls_before


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("redirect", "approved HTTPS endpoint"),
        ("media-type", "did not return HTML"),
        ("content-encoding", "unsupported content encoding"),
        ("status", "non-success HTTP status"),
        ("length", "Content-Length"),
        ("length-mismatch", "did not match its declared Content-Length"),
    ],
)
def test_transport_fails_closed(mutation: str, message: str) -> None:
    opener, iana_raw, _ = _opener()
    response = opener.responses[source_freezer.IANA_URL]
    if mutation == "redirect":
        response._url = "https://example.test/domains/root/db"
    elif mutation == "media-type":
        response.headers.replace_header("Content-Type", "application/json")
    elif mutation == "content-encoding":
        response.headers["Content-Encoding"] = "gzip"
    elif mutation == "status":
        response.status = 503
    elif mutation == "length":
        response.headers.replace_header("Content-Length", str(source_freezer.IANA_MAX_BYTES + 1))
    else:
        response.headers.replace_header("Content-Length", str(len(iana_raw) - 1))

    with pytest.raises(ValueError, match=message):
        source_freezer._download(
            source_freezer.IANA_URL,
            maximum_bytes=max(len(iana_raw), 1),
            opener=opener,
        )


def test_default_transport_rejects_redirect_before_following() -> None:
    handler = source_freezer._RejectRedirects()

    with pytest.raises(ValueError, match="redirects are not allowed"):
        handler.redirect_request(
            urllib.request.Request(source_freezer.IANA_URL),  # noqa: S310 - fixed test URL
            object(),
            302,
            "Found",
            Message(),
            "https://example.com/unapproved",
        )


def test_response_read_limit_is_enforced() -> None:
    raw = b"x" * 11
    response = FakeResponse(raw, source_freezer.IANA_URL, declared_length="10")
    opener = FakeOpener({source_freezer.IANA_URL: response})

    with pytest.raises(ValueError, match="exceeded the bounded response limit"):
        source_freezer._download(source_freezer.IANA_URL, maximum_bytes=10, opener=opener)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("iana-header", "IANA root-zone table header changed"),
        ("iana-duplicate", "duplicates a country-code TLD"),
        ("un-header", "UN M49 English table header changed"),
        ("un-alpha2", "invalid ISO alpha-2 code"),
        ("un-region", "unexpected region mapping"),
        ("un-duplicate", "duplicates an ISO alpha-2 code"),
    ],
)
def test_source_tables_fail_closed_on_semantic_drift(mutation: str, message: str) -> None:
    codes = _alpha2_codes()
    iana_raw = _iana_html(codes)
    un_raw = _un_html(codes)
    if mutation == "iana-header":
        iana_raw = iana_raw.replace(b">Domain<", b">Suffix<", 1)
    elif mutation == "iana-duplicate":
        duplicate = f"<tr><td>.{codes[0].casefold()}</td><td>country-code</td><td>Duplicate</td></tr>".encode()
        iana_raw = iana_raw.replace(b"</table>", duplicate + b"</table>")
    elif mutation == "un-header":
        un_raw = un_raw.replace(b">ISO-alpha2 Code<", b">Alpha Code<", 1)
    elif mutation == "un-alpha2":
        un_raw = un_raw.replace(f">{codes[0]}<".encode(), b">BAD<", 1)
    elif mutation == "un-region":
        un_raw = un_raw.replace(b">Africa<", b">Unexpected<", 1)
    else:
        un_raw = un_raw.replace(f">{codes[1]}<".encode(), f">{codes[0]}<".encode(), 1)

    check = source_freezer._iana_country_codes if mutation.startswith("iana") else source_freezer._un_m49_codes
    source = iana_raw if mutation.startswith("iana") else un_raw
    with pytest.raises(ValueError, match=message):
        check(source)


def test_missing_duplicate_and_incomplete_tables_are_rejected() -> None:
    missing = b"<html><table id='other'><tr><td>x</td></tr></table></html>"
    duplicate = b"<table id='wanted'><tr><td>x</td></tr></table>" * 2
    incomplete = b"<table id='wanted'><tr><td>x</td>"

    with pytest.raises(ValueError, match="exactly one"):
        source_freezer._table_rows(missing, table_id="wanted", source_name="fixture")
    with pytest.raises(ValueError, match="exactly one"):
        source_freezer._table_rows(duplicate, table_id="wanted", source_name="fixture")
    with pytest.raises(ValueError, match="incomplete"):
        source_freezer._table_rows(incomplete, table_id="wanted", source_name="fixture")


def test_regionless_m49_row_is_accounted_for_and_excluded() -> None:
    codes = _alpha2_codes()
    raw = _un_html(codes)
    raw = raw.replace(b">002</td><td>Africa<", b"></td><td><", 1)

    parsed, accounting = source_freezer._un_m49_codes(raw)

    assert codes[0] not in parsed
    assert accounting == {
        "table_rows": 205,
        "iso_alpha2_rows": 205,
        "canonical_region_iso_alpha2_rows": 204,
        "regionless_iso_alpha2_rows_excluded": 1,
    }


def test_scale_and_timestamp_guards_reject_partial_or_ambiguous_freezes(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="IANA root-zone table size"):
        source_freezer._validate_scale(
            {"table_rows": 999, "country_code_rows": 250},
            {"table_rows": 240},
            230,
        )

    opener, _, _ = _opener()
    with pytest.raises(ValueError, match="UTC timezone"):
        source_freezer.prepare_source_freeze(
            tmp_path / "private" / "sources",
            opener=cast(source_freezer.OpenUrl, opener),
            retrieved_at="2026-08-13T20:00:00",
        )
