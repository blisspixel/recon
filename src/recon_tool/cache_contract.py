"""Shared result-cache format and freshness limits."""

from __future__ import annotations

DEFAULT_TTL: int = 86400
RESULT_CACHE_VERSION = 3
MAX_RESULT_CACHE_FILE_BYTES = 5 * 1024 * 1024
