"""RFC 8461 policy-fetch and parsing regressions."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from recon_tool.sources.dns_email import _fetch_mta_sts_policy
from recon_tool.sources.mta_sts import is_plain_text_policy, parse_mta_sts_policy, select_mta_sts_record

_URL = "https://mta-sts.example.com/.well-known/mta-sts.txt"
_VALID_ENFORCE = "\n".join(
    (
        "version: STSv1",
        "mode: enforce",
        "mx: mail.example.com",
        "max_age: 86400",
        "",
    )
)


def test_mta_sts_record_selector_accepts_one_complete_record() -> None:
    record = "v=STSv1; id=20260801; extension=value"
    assert select_mta_sts_record(("unrelated=value", record)) == record


@pytest.mark.parametrize(
    "records",
    [
        (),
        ("v=STSv1",),
        ("v=STSv1;",),
        ("v=STSv1; id=",),
        ("v=STSv1; id=contains-hyphen",),
        ("prefix v=STSv1; id=20260801",),
        ("v=stsv1; id=20260801",),
        ("v=STSv1; id=20260801; extension=contains space",),
        ("v=STSv1; id=one", "v=STSv1; id=two"),
    ],
)
def test_mta_sts_record_selector_rejects_missing_ambiguous_or_malformed_records(
    records: tuple[str, ...],
) -> None:
    assert select_mta_sts_record(records) is None


def _response(status: int, body: str = "", *, content_type: str | None = "text/plain") -> httpx.Response:
    headers = {} if content_type is None else {"content-type": content_type}
    return httpx.Response(status, content=body.encode(), headers=headers, request=httpx.Request("GET", _URL))


@pytest.mark.asyncio
async def test_mta_sts_fetch_disables_redirects_at_the_request() -> None:
    client = AsyncMock()
    client.get = AsyncMock(return_value=_response(302))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    with patch("recon_tool.sources.dns_email._http_client", return_value=client):
        mode = await _fetch_mta_sts_policy("example.com")

    assert mode is None
    client.get.assert_awaited_once_with(_URL, follow_redirects=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("content_type", [None, "text/html", "application/octet-stream"])
async def test_mta_sts_fetch_rejects_non_plain_policy_media(content_type: str | None) -> None:
    client = AsyncMock()
    client.get = AsyncMock(return_value=_response(200, _VALID_ENFORCE, content_type=content_type))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    with patch("recon_tool.sources.dns_email._http_client", return_value=client):
        mode = await _fetch_mta_sts_policy("example.com")

    assert mode is None


def test_mta_sts_parser_accepts_complete_policy_and_extensions() -> None:
    body = _VALID_ENFORCE.replace(
        "max_age: 86400",
        "reporting_id: synthetic café 東京 𐍈 report\nmax_age: 86400",
    )
    assert parse_mta_sts_policy(body.encode()) == "enforce"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("version: STSv1\nmode: none\nmax_age: 0\n", "none"),
        ("version: STSv1\nmode: testing\nmx: *.EXAMPLE.com\nmax_age: 31557600\n", "testing"),
        ("version: STSv1\nmode: enforce\nmx: www.example.com\nmax_age: 86400\n", "enforce"),
        ("version: STSv1\nmode: enforce\nmx: www.www.example.com\nmax_age: 86400\n", "enforce"),
        ("version: STSv1\nmode: enforce\nmx: mx1\nmax_age: 86400\n", "enforce"),
        ("version: STSv1\nmode: enforce\nmx: mail.example.123\nmax_age: 86400\n", "enforce"),
    ],
)
def test_mta_sts_parser_accepts_each_complete_policy_shape(body: str, expected: str) -> None:
    assert parse_mta_sts_policy(body.encode()) == expected


@pytest.mark.parametrize(
    ("content_type", "expected"),
    [
        ("text/plain", True),
        ("TEXT/PLAIN; charset=UTF-8", True),
        ('text/plain; charset="us-ascii"; profile=synthetic', True),
        ("text/plain; charset=iso-8859-1", False),
        ("text/html", False),
        (None, False),
    ],
)
def test_mta_sts_media_type_admission(content_type: str | None, expected: bool) -> None:
    assert is_plain_text_policy(content_type) is expected


def test_mta_sts_parser_uses_first_non_repeated_field() -> None:
    body = "version: STSv1\nmode: none\nmode: enforce\nmax_age: 0\n"
    assert parse_mta_sts_policy(body.encode()) == "none"


@pytest.mark.parametrize(
    "body",
    [
        "mode: enforce\nmx: mail.example.com\nmax_age: 86400\n",
        "version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n",
        "version: STSv1\nmode: enforce\nmx: mail.example.com\n",
        "version: STSv1\nmode: enforce\nmax_age: 86400\n",
        "version: STSv1\nmode: enforce\nmx: invalid_host\nmax_age: 86400\n",
        "version: STSv1\nmode: enforce\nmx: mail.example.com.\nmax_age: 86400\n",
        "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 31557601\n",
        "version: STSv1\nmode: enforce\nmx: mail.example.com\nnote: good\tbad\nmax_age: 86400\n",
        "version: STSv1\nmode: disabled\nmx: mail.example.com\nmax_age: 86400\n",
        "version: STSv1\nmode enforce\nmx: mail.example.com\nmax_age: 86400\n",
        "version: STSv1\rmode: enforce\nmx: mail.example.com\nmax_age: 86400\n",
        "version: STSv1\n\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n",
    ],
)
def test_mta_sts_parser_rejects_malformed_or_incomplete_policy(body: str) -> None:
    assert parse_mta_sts_policy(body.encode()) is None


def test_mta_sts_parser_rejects_policy_above_rfc_size_guidance() -> None:
    body = _VALID_ENFORCE + ("x" * (64 * 1024))
    assert parse_mta_sts_policy(body.encode()) is None


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=70 * 1024))
def test_mta_sts_parser_is_total_for_arbitrary_bounded_bytes(content: bytes) -> None:
    assert parse_mta_sts_policy(content) in {"enforce", "testing", "none", None}
