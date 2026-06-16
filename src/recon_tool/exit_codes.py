"""Process exit codes for the recon CLI.

Single source of truth for the codes the CLI and the MCP server entry
point return, so a scripter sees one stable contract and every call site
names a constant instead of a bare integer literal.

The contract (documented for consumers in ``docs/schema.md``):

* ``0`` success: the command completed and produced its output.
* ``1`` general error: an unexpected or uncaught failure, plus the few
  handled fallbacks that are neither a clean validation nor no-data case
  (an optional MCP dependency missing, an unexpected MCP server fault).
  This is the Python default for an uncaught exception, so it also
  covers paths recon does not explicitly classify.
* ``2`` validation error: bad input that recon rejected before doing
  work (malformed domain, missing file, mutually exclusive flags, a
  refused unsafe invocation).
* ``3`` no data: the target resolved but no information was available.
* ``4`` internal error: recon classified its own failure (a network or
  pipeline error it caught and reported) rather than letting it surface
  as an uncaught ``1``.

Codes ``2``, ``3``, and ``4`` are the ones the lookup and delta paths
emit deliberately; ``1`` is the general fallback; ``0`` is success.
"""

from __future__ import annotations

EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_VALIDATION = 2
EXIT_NO_DATA = 3
EXIT_INTERNAL = 4

__all__ = [
    "EXIT_ERROR",
    "EXIT_INTERNAL",
    "EXIT_NO_DATA",
    "EXIT_SUCCESS",
    "EXIT_VALIDATION",
]
