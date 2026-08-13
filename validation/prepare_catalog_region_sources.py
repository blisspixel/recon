"""Freeze authoritative IANA and UN M49 inputs for a regional catalog round.

The command makes exactly two bounded HTTPS requests to fixed official source
pages. It stores the raw responses, their exact ASCII ccTLD intersection, and
an integrity manifest under a private validation root. It never contacts a
selected namespace and prints only aggregate counts and commitments.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import json
import os
import re
import urllib.request
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import Message
from html.parser import HTMLParser
from pathlib import Path
from types import TracebackType
from typing import NoReturn, Protocol, cast
from urllib.parse import urlsplit

from validation.prepare_catalog_round import execution_digest_sha256
from validation.ranked_sampling import digest_bytes
from validation.run_path_safety import validate_private_output_root

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOTS = (
    REPO_ROOT / "validation" / "corpus-private",
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "local",
)
SCHEMA_VERSION = 1
IANA_URL = "https://www.iana.org/domains/root/db"
UN_M49_URL = "https://unstats.un.org/unsd/methodology/m49/overview/"
IANA_TABLE_ID = "tld-table"
UN_M49_TABLE_ID = "downloadTableEN"
IANA_MAX_BYTES = 1024 * 1024
UN_M49_MAX_BYTES = 4 * 1024 * 1024
HTTP_TIMEOUT_SECONDS = 30.0
MAPPING_COLUMNS = ("tld", "iana_type", "iso_alpha2", "region_code", "region_name")
IANA_HEADER = ("Domain", "Type", "TLD Manager")
UN_M49_HEADER = (
    "Global Code",
    "Global Name",
    "Region Code",
    "Region Name",
    "Sub-region Code",
    "Sub-region Name",
    "Intermediate Region Code",
    "Intermediate Region Name",
    "Country or Area",
    "M49 Code",
    "ISO-alpha2 Code",
    "ISO-alpha3 Code",
    "Least Developed Countries (LDC)",
    "Land Locked Developing Countries (LLDC)",
    "Small Island Developing States (SIDS)",
)
CANONICAL_REGIONS = {
    "002": "Africa",
    "019": "Americas",
    "142": "Asia",
    "150": "Europe",
    "009": "Oceania",
}
OUTPUT_NAMES = {
    "iana": "iana-root-zone-database.html",
    "un_m49": "un-m49-overview-en.html",
    "mapping": "iana-un-m49-cctld.csv",
    "manifest": "region-source-manifest" + "." + "json",
}
_ASCII_CCTLD = re.compile(r"^\.[a-z]{2}$")
_ALPHA2 = re.compile(r"^[A-Z]{2}$")


class HttpResponse(Protocol):
    """Bounded surface used from an urllib response."""

    headers: Message
    status: int

    def read(self, amount: int = -1) -> bytes: ...

    def geturl(self) -> str: ...

    def __enter__(self) -> HttpResponse: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...


class OpenUrl(Protocol):
    """Callable shape for a fixed-source HTTPS opener."""

    def __call__(self, request: urllib.request.Request, *, timeout: float) -> HttpResponse: ...


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Stop redirects before urllib can contact a second endpoint."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        _fail("official source redirects are not allowed")


@dataclass(frozen=True, slots=True)
class FrozenSource:
    """One bounded official response and its transport metadata."""

    expected_url: str
    final_url: str
    media_type: str
    raw: bytes


@dataclass(frozen=True, slots=True)
class RegionMapping:
    """One exact ASCII ccTLD and UN M49 region intersection row."""

    tld: str
    alpha2: str
    region_code: str
    region_name: str


class _TargetTableParser(HTMLParser):
    """Collect normalized cells from one exact HTML table id."""

    def __init__(self, table_id: str) -> None:
        super().__init__(convert_charrefs=True)
        self._table_id = table_id
        self._table_depth = 0
        self._matches = 0
        self._current_row: list[str] | None = None
        self._current_cell: list[str] | None = None
        self.rows: list[tuple[str, ...]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.casefold()
        if lowered == "table":
            if self._table_depth:
                self._table_depth += 1
                return
            attributes = {key.casefold(): value for key, value in attrs}
            if attributes.get("id") == self._table_id:
                self._matches += 1
                self._table_depth = 1
            return
        if self._table_depth != 1:
            return
        if lowered == "tr":
            self._current_row = []
        elif lowered in {"td", "th"} and self._current_row is not None:
            self._current_cell = []

    def handle_data(self, data: str) -> None:
        if self._table_depth == 1 and self._current_cell is not None:
            self._current_cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        if lowered == "table" and self._table_depth:
            self._table_depth -= 1
            return
        if self._table_depth != 1:
            return
        if lowered in {"td", "th"} and self._current_cell is not None:
            if self._current_row is None:
                _fail(f"HTML table {self._table_id!r} contains a cell outside a row")
            self._current_row.append(" ".join("".join(self._current_cell).split()))
            self._current_cell = None
        elif lowered == "tr" and self._current_row is not None:
            if self._current_row:
                self.rows.append(tuple(self._current_row))
            self._current_row = None

    def validated_rows(self) -> tuple[tuple[str, ...], ...]:
        """Return the single complete table or reject structural drift."""
        if self._matches != 1:
            raise ValueError(f"expected exactly one HTML table with id {self._table_id!r}")
        if self._table_depth or self._current_row is not None or self._current_cell is not None:
            raise ValueError(f"HTML table {self._table_id!r} is incomplete")
        if not self.rows:
            raise ValueError(f"HTML table {self._table_id!r} has no rows")
        return tuple(self.rows)


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _private_output_directory(path: Path) -> Path:
    return validate_private_output_root(path.resolve(strict=False), repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def _timestamp(value: str | None) -> str:
    timestamp = value or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("retrieved_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        _fail("retrieved_at must carry the UTC timezone")
    return timestamp


def _validate_final_url(expected: str, actual: str) -> None:
    expected_parts = urlsplit(expected)
    actual_parts = urlsplit(actual)
    try:
        invalid = (
            actual_parts.scheme != "https"
            or actual_parts.hostname != expected_parts.hostname
            or actual_parts.port not in {None, 443}
            or actual_parts.username is not None
            or actual_parts.password is not None
            or actual_parts.path.rstrip("/") != expected_parts.path.rstrip("/")
            or actual_parts.query != expected_parts.query
            or bool(actual_parts.fragment)
        )
    except ValueError:
        invalid = True
    if invalid:
        _fail("official source redirected outside its exact approved HTTPS endpoint")


def _download(url: str, *, maximum_bytes: int, opener: OpenUrl) -> FrozenSource:
    request = urllib.request.Request(  # noqa: S310 - both callable URLs are fixed HTTPS constants.
        url,
        headers={
            "Accept": "text/html",
            "Accept-Encoding": "identity",
            "User-Agent": "recon-validation/2.14 (+https://github.com/blisspixel/recon)",
        },
        method="GET",
    )
    with opener(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        if response.status != 200:
            _fail("official source returned a non-success HTTP status")
        final_url = response.geturl()
        _validate_final_url(url, final_url)
        content_type = response.headers.get("Content-Type", "")
        media_type = content_type.partition(";")[0].strip().casefold()
        if media_type not in {"text/html", "application/xhtml+xml"}:
            _fail("official source did not return HTML")
        content_encoding = response.headers.get("Content-Encoding", "").strip().casefold()
        if content_encoding not in {"", "identity"}:
            _fail("official source returned an unsupported content encoding")
        declared_length = response.headers.get("Content-Length")
        expected_length: int | None = None
        if declared_length is not None:
            try:
                expected_length = int(declared_length)
            except ValueError as exc:
                raise ValueError("official source returned an invalid Content-Length") from exc
            if expected_length < 1 or expected_length > maximum_bytes:
                _fail("official source Content-Length is outside the bounded response limit")
        raw = response.read(maximum_bytes + 1)
    if not raw:
        _fail("official source returned an empty response")
    if len(raw) > maximum_bytes:
        _fail("official source exceeded the bounded response limit")
    if expected_length is not None and len(raw) != expected_length:
        _fail("official source body did not match its declared Content-Length")
    return FrozenSource(url, final_url, media_type, raw)


def _table_rows(raw: bytes, *, table_id: str, source_name: str) -> tuple[tuple[str, ...], ...]:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{source_name} is not UTF-8") from exc
    parser = _TargetTableParser(table_id)
    parser.feed(text)
    parser.close()
    return parser.validated_rows()


def _iana_country_codes(raw: bytes) -> tuple[set[str], dict[str, int]]:
    rows = _table_rows(raw, table_id=IANA_TABLE_ID, source_name="IANA root-zone database")
    if rows[0] != IANA_HEADER:
        _fail("IANA root-zone table header changed")
    country_codes: set[str] = set()
    ascii_country_codes: set[str] = set()
    for physical_row, row in enumerate(rows[1:], start=2):
        if len(row) != len(IANA_HEADER):
            _fail(f"IANA root-zone table row {physical_row} has an invalid column count")
        domain, tld_type, _manager = row
        if tld_type != "country-code":
            continue
        normalized = domain.casefold()
        if normalized in country_codes:
            _fail(f"IANA root-zone table row {physical_row} duplicates a country-code TLD")
        country_codes.add(normalized)
        if _ASCII_CCTLD.fullmatch(normalized) is not None:
            ascii_country_codes.add(normalized[1:])
    return ascii_country_codes, {
        "table_rows": len(rows) - 1,
        "country_code_rows": len(country_codes),
        "ascii_two_letter_country_code_rows": len(ascii_country_codes),
    }


def _un_m49_codes(raw: bytes) -> tuple[dict[str, tuple[str, str]], dict[str, int]]:
    rows = _table_rows(raw, table_id=UN_M49_TABLE_ID, source_name="UN M49 overview")
    if rows[0] != UN_M49_HEADER:
        _fail("UN M49 English table header changed")
    codes: dict[str, tuple[str, str]] = {}
    all_codes: set[str] = set()
    regionless_rows = 0
    for physical_row, row in enumerate(rows[1:], start=2):
        if len(row) != len(UN_M49_HEADER):
            _fail(f"UN M49 table row {physical_row} has an invalid column count")
        region_code = row[2]
        region_name = row[3]
        alpha2 = row[10]
        if _ALPHA2.fullmatch(alpha2) is None:
            _fail(f"UN M49 table row {physical_row} has an invalid ISO alpha-2 code")
        if alpha2 in all_codes:
            _fail(f"UN M49 table row {physical_row} duplicates an ISO alpha-2 code")
        all_codes.add(alpha2)
        if not region_code and not region_name:
            regionless_rows += 1
            continue
        if CANONICAL_REGIONS.get(region_code) != region_name:
            _fail(f"UN M49 table row {physical_row} has an unexpected region mapping")
        codes[alpha2] = (region_code, region_name)
    return codes, {
        "table_rows": len(rows) - 1,
        "iso_alpha2_rows": len(all_codes),
        "canonical_region_iso_alpha2_rows": len(codes),
        "regionless_iso_alpha2_rows_excluded": regionless_rows,
    }


def _intersection(
    iana_codes: set[str],
    un_codes: Mapping[str, tuple[str, str]],
) -> tuple[list[RegionMapping], dict[str, object]]:
    rows = [
        RegionMapping(tld, tld.upper(), *un_codes[tld.upper()]) for tld in sorted(iana_codes) if tld.upper() in un_codes
    ]
    region_counts = Counter(row.region_code for row in rows)
    if set(region_counts) != set(CANONICAL_REGIONS):
        _fail("IANA and UN M49 intersection does not cover every canonical region")
    return rows, {
        "intersection_rows": len(rows),
        "iana_ascii_rows_without_m49_match": len(iana_codes) - len(rows),
        "un_alpha2_rows_without_iana_match": len(un_codes) - len(rows),
        "region_rows": [
            {"code": code, "name": name, "rows": region_counts[code]} for code, name in CANONICAL_REGIONS.items()
        ],
    }


def _validate_scale(
    iana_accounting: Mapping[str, int],
    un_accounting: Mapping[str, int],
    mapping_rows: int,
) -> None:
    checks = (
        (1000 <= iana_accounting["table_rows"] <= 2500, "IANA root-zone table size"),
        (200 <= iana_accounting["country_code_rows"] <= 400, "IANA country-code row count"),
        (200 <= un_accounting["table_rows"] <= 300, "UN M49 row count"),
        (180 <= mapping_rows <= 260, "IANA and UN M49 intersection size"),
    )
    for valid, label in checks:
        if not valid:
            _fail(f"{label} is outside its fail-closed safety range")


def _mapping_bytes(rows: Sequence[RegionMapping]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(MAPPING_COLUMNS)
    for row in rows:
        writer.writerow((row.tld, "country-code", row.alpha2, row.region_code, row.region_name))
    return stream.getvalue().encode("ascii")


def prepare_source_freeze(
    output_directory: Path,
    *,
    opener: OpenUrl | None = None,
    retrieved_at: str | None = None,
) -> tuple[dict[str, bytes], dict[str, object]]:
    """Fetch, validate, and return private official-source freeze artifacts."""
    output_root = _private_output_directory(output_directory)
    fixed_source_opener = urllib.request.build_opener(_RejectRedirects())
    actual_opener = opener or cast(OpenUrl, fixed_source_opener.open)
    iana = _download(IANA_URL, maximum_bytes=IANA_MAX_BYTES, opener=actual_opener)
    un_m49 = _download(UN_M49_URL, maximum_bytes=UN_M49_MAX_BYTES, opener=actual_opener)
    iana_codes, iana_accounting = _iana_country_codes(iana.raw)
    un_codes, un_accounting = _un_m49_codes(un_m49.raw)
    mapping_rows, intersection_accounting = _intersection(iana_codes, un_codes)
    _validate_scale(iana_accounting, un_accounting, len(mapping_rows))
    mapping_raw = _mapping_bytes(mapping_rows)
    outputs = {
        OUTPUT_NAMES["iana"]: iana.raw,
        OUTPUT_NAMES["un_m49"]: un_m49.raw,
        OUTPUT_NAMES["mapping"]: mapping_raw,
    }
    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "retrieved_at": _timestamp(retrieved_at),
        "sources": {
            "iana": {
                "url": iana.expected_url,
                "final_url": iana.final_url,
                "media_type": iana.media_type,
                "private_file": str(output_root / OUTPUT_NAMES["iana"]),
                "bytes": len(iana.raw),
                "sha256": digest_bytes(iana.raw),
                **iana_accounting,
            },
            "un_m49": {
                "url": un_m49.expected_url,
                "final_url": un_m49.final_url,
                "media_type": un_m49.media_type,
                "private_file": str(output_root / OUTPUT_NAMES["un_m49"]),
                "bytes": len(un_m49.raw),
                "sha256": digest_bytes(un_m49.raw),
                **un_accounting,
            },
        },
        "mapping": {
            "private_file": str(output_root / OUTPUT_NAMES["mapping"]),
            "columns": list(MAPPING_COLUMNS),
            "rows": len(mapping_rows),
            "bytes": len(mapping_raw),
            "sha256": digest_bytes(mapping_raw),
            "rule": "exact ASCII two-letter IANA country-code TLD and UN M49 ISO-alpha2 intersection",
            **intersection_accounting,
        },
        "implementation": {"execution_sha256": execution_digest_sha256()},
        "privacy": {
            "official_source_requests": 2,
            "target_namespace_requests": 0,
            "target_identifiers_printed": 0,
        },
    }
    manifest["manifest_digest_sha256"] = digest_bytes(_canonical_json(manifest))
    return outputs, manifest


def public_summary(manifest: Mapping[str, object], *, written: bool) -> dict[str, object]:
    """Return a path-free aggregate summary for standard output."""
    sources = cast(Mapping[str, Mapping[str, object]], manifest["sources"])
    mapping = cast(Mapping[str, object], manifest["mapping"])
    return {
        "schema_version": manifest["schema_version"],
        "retrieved_at": manifest["retrieved_at"],
        "sources": {
            name: {key: value for key, value in source.items() if key != "private_file"}
            for name, source in sources.items()
        },
        "mapping": {key: value for key, value in mapping.items() if key != "private_file"},
        "implementation": manifest["implementation"],
        "manifest_digest_sha256": manifest["manifest_digest_sha256"],
        "privacy": {
            **cast(Mapping[str, object], manifest["privacy"]),
            "private_artifacts_written": written,
        },
    }


def _reserve(path: Path) -> int:
    try:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("private regional source artifact already exists; refusing to replace it") from exc


def write_source_freeze(
    output_directory: Path,
    *,
    opener: OpenUrl | None = None,
    retrieved_at: str | None = None,
) -> dict[str, object]:
    """Fetch and exclusively write the complete private source freeze."""
    output_root = _private_output_directory(output_directory)
    expected_paths = [output_root / filename for filename in OUTPUT_NAMES.values()]
    if any(path.exists() for path in expected_paths):
        _fail("private regional source artifact already exists; refusing to replace it")
    outputs, manifest = prepare_source_freeze(output_root, opener=opener, retrieved_at=retrieved_at)
    complete_outputs = {
        **outputs,
        OUTPUT_NAMES["manifest"]: json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    }
    output_root.mkdir(parents=True, exist_ok=True)
    owned: list[Path] = []
    descriptors: dict[Path, int] = {}
    try:
        for filename in complete_outputs:
            path = output_root / filename
            descriptors[path] = _reserve(path)
            owned.append(path)
        for filename, payload in complete_outputs.items():
            path = output_root / filename
            descriptor = descriptors.pop(path)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
    except Exception:
        for descriptor in descriptors.values():
            os.close(descriptor)
        for path in owned:
            with contextlib.suppress(OSError):
                path.unlink()
        raise
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    manifest = write_source_freeze(args.output_directory)
    print(json.dumps(public_summary(manifest, written=True), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
