"""Process exit codes for the recon CLI.

Single source of truth for the codes the CLI and the MCP server entry
point return, so a scripter sees one stable contract and every call site
names a constant instead of a bare integer literal.

The contract (documented for consumers in ``docs/schema.md``):

* ``0`` success: the command completed and produced its output.
* ``1`` general error: an explicitly handled command or server failure that
  is neither a clean validation, no-data, nor caught pipeline case (for
  example, a missing optional MCP dependency or a failed doctor check). It is
  also Python's default when an exception escapes before recon's CLI
  last-resort handler is active, or from an alternate entry point without that
  handler.
* ``2`` validation error: bad input that recon rejected before doing
  work (malformed domain, missing file, mutually exclusive flags, a
  refused unsafe invocation).
* ``3`` no data: the target resolved but no information was available.
* ``4`` internal error: recon caught and classified a network or pipeline
  failure, or the CLI last-resort handler caught an unexpected runtime crash
  and reported its local crash-artifact path.

Codes ``2``, ``3``, and ``4`` are the ones the lookup and delta paths emit
deliberately; the top-level CLI crash handler also emits ``4``. Code ``1`` is
the explicitly handled general failure and pre-handler fallback; ``0`` is
success.
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
