"""Small shared helpers for the cli modules.

Helpers used by more than one cli module live here so the sibling sub-app
modules (`cli_fingerprints`, etc.) can import them without reaching back into
`cli.py`, which would be a circular import. Public names because they cross a
module boundary (pyright-strict flags cross-module underscore access); the
callers alias them back to their historical `_name` where convenient.
"""

from __future__ import annotations


def fmt_exc(exc: BaseException) -> str:
    """Render an exception for user display, falling back to the type name.

    httpx.ReadTimeout and similar raise with an empty message, which used
    to render as ``FAIL  crt.sh — `` with nothing after the em-dash.
    """
    return str(exc) or type(exc).__name__
