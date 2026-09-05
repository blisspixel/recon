"""Exclusion encoding must not silently admit development namespaces."""

from __future__ import annotations

from pathlib import Path

import pytest

from validation.ranked_sampling import read_exclusions


@pytest.mark.parametrize("prefix", [b"", b"\xef\xbb\xbf"])
def test_exclusion_utf8_signature_does_not_drop_first_namespace(tmp_path: Path, prefix: bytes) -> None:
    raw = prefix + b"alpha.invalid\nwww.beta.invalid\nalpha.invalid\n"
    path = tmp_path / "exclusions.txt"
    path.write_bytes(raw)

    domains, committed, rows, normalized, duplicates, invalid = read_exclusions(path)

    assert domains == {"alpha.invalid", "beta.invalid"}
    assert committed == raw
    assert (rows, normalized, duplicates, invalid) == (3, 1, 1, 0)


def test_signature_before_comment_is_not_counted_as_an_exclusion(tmp_path: Path) -> None:
    path = tmp_path / "exclusions.txt"
    path.write_bytes(b"\xef\xbb\xbf# frozen development namespace list\nalpha.invalid\n")

    domains, _, rows, normalized, duplicates, invalid = read_exclusions(path)

    assert domains == {"alpha.invalid"}
    assert (rows, normalized, duplicates, invalid) == (1, 0, 0, 0)


def test_embedded_signature_is_not_silently_stripped_from_a_domain(tmp_path: Path) -> None:
    path = tmp_path / "exclusions.txt"
    path.write_bytes(b"alpha.invalid\n\xef\xbb\xbfbeta.invalid\n")

    domains, _, rows, normalized, duplicates, invalid = read_exclusions(path)

    assert domains == {"alpha.invalid"}
    assert (rows, normalized, duplicates, invalid) == (2, 0, 0, 1)
