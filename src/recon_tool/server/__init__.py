"""MCP server for recon — domain intelligence.

Exposes lookup tool, reload tool, and prompt template over stdio transport.
Read-only (lookup) and idempotent, queries public endpoints and DNS.

Includes a bounded TTL cache for resolved results (default 120s, max 1000 entries)
to avoid hammering upstream endpoints when an AI agent calls lookup_tenant
repeatedly, and a bounded per-domain rate limiter to prevent abuse.
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager

from recon_tool.exit_codes import EXIT_ERROR, EXIT_VALIDATION
from recon_tool.server import app as server_app
from recon_tool.server import ephemeral as server_ephemeral
from recon_tool.server import graph as server_graph
from recon_tool.server import introspection as server_introspection
from recon_tool.server import lookup as server_lookup
from recon_tool.server import posture as server_posture
from recon_tool.server import runtime as _server_runtime
from recon_tool.server.app import mcp
from recon_tool.validator import strip_control_chars, validate_domain

logger = logging.getLogger("recon")

_MAX_FATAL_DETAIL = 500


@contextmanager
def _runtime_logging() -> Generator[None]:
    """Provide default MCP stderr logging only while the server is running."""
    if logger.hasHandlers():
        yield
        return

    previous_level = logger.level
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield
    finally:
        logger.removeHandler(handler)
        handler.close()
        logger.setLevel(previous_level)


def _fatal_detail(exc: BaseException) -> str:
    """Return one bounded terminal-safe detail for an unexpected MCP exit."""
    raw = str(exc)
    single_line = " ".join(raw.splitlines())
    detail = strip_control_chars(single_line, max_len=_MAX_FATAL_DETAIL) or "no detail provided"
    if len(raw) > _MAX_FATAL_DETAIL:
        detail = f"{detail} [truncated]"
    return detail


# Re-export facade: the FastMCP instance and instructions live in
# recon_tool.server.app; preserve the recon_tool.server import path for the
# test surface.
_SERVER_INSTRUCTIONS = server_app.SERVER_INSTRUCTIONS

# Tool-group re-export facades (registration via the imports above).
lookup_tenant = server_lookup.lookup_tenant
analyze_posture = server_posture.analyze_posture
assess_exposure = server_posture.assess_exposure
find_hardening_gaps = server_posture.find_hardening_gaps
compare_postures = server_posture.compare_postures
test_hypothesis = server_posture.test_hypothesis
simulate_hardening = server_posture.simulate_hardening
chain_lookup = server_graph.chain_lookup
cluster_verification_tokens = server_graph.cluster_verification_tokens
get_infrastructure_clusters = server_graph.get_infrastructure_clusters
export_graph = server_graph.export_graph
get_fingerprints = server_introspection.get_fingerprints
get_signals = server_introspection.get_signals
explain_signal = server_introspection.explain_signal
reload_data = server_introspection.reload_data
discover_fingerprint_candidates = server_introspection.discover_fingerprint_candidates
get_posteriors = server_introspection.get_posteriors
explain_dag = server_introspection.explain_dag

# Tool-group re-export facade (registration via the import above): preserve
# the recon_tool.server import path for the tool functions the tests import.
inject_ephemeral_fingerprint = server_ephemeral.inject_ephemeral_fingerprint
list_ephemeral_fingerprints = server_ephemeral.list_ephemeral_fingerprints
clear_ephemeral_fingerprints = server_ephemeral.clear_ephemeral_fingerprints
reevaluate_domain = server_ephemeral.reevaluate_domain

# Re-export facade for the server runtime state (see recon_tool.server.runtime).
# Preserves the recon_tool.server import path for the tools and tests.
CACHE_TTL = _server_runtime.CACHE_TTL
CACHE_MAX_SIZE = _server_runtime.CACHE_MAX_SIZE
RATE_LIMIT_WINDOW = _server_runtime.RATE_LIMIT_WINDOW
_RATE_LIMIT_MAX_SIZE = _server_runtime.RATE_LIMIT_MAX_SIZE
_cache = _server_runtime.cache
_rate_limit = _server_runtime.rate_limit
_cache_evict_expired = _server_runtime.cache_evict_expired
_cache_get = _server_runtime.cache_get
_cache_set = _server_runtime.cache_set
_cache_clear = _server_runtime.cache_clear
_cache_refresh_info = _server_runtime.cache_refresh_info
_remerge_cached_infos = _server_runtime.remerge_cached_infos
_rate_limit_evict_expired = _server_runtime.rate_limit_evict_expired
_rate_limit_check = _server_runtime.rate_limit_check
_rate_limit_record = _server_runtime.rate_limit_record
_rate_limit_try_acquire = _server_runtime.rate_limit_try_acquire
_rate_limit_clear = _server_runtime.rate_limit_clear
_log_structured = _server_runtime.log_structured


# ── Bounded TTL cache for resolved results ──────────────────────────────
# Prevents hammering upstream endpoints when an AI agent calls lookup_tenant
# repeatedly for the same domain. Cache entries expire after CACHE_TTL seconds.
# Max size prevents unbounded memory growth from unique domain lookups.
#
# The MCP server currently runs as a single-process stdio transport, so a small
# in-process state container is enough. Keeping cache and rate-limiter behavior
# together in one typed object makes the bounded-size and lifetime invariants
# easier to reason about and test.


# ── Bounded per-domain rate limiter ─────────────────────────────────────
# Prevents abuse by limiting how often the same domain can be looked up
# (cache misses only). Uses a simple timestamp-based approach with periodic
# eviction to prevent unbounded memory growth.


# ── MCP resources ────────────────────────────────────────────────────
# Catalog resources let agents browse "what can recon detect?" without
# spending a tool invocation on introspection. Read-only. The content
# is a deterministic projection over the already-loaded YAML catalogs;
# changes require reload_data to take effect. No network calls.


# ── Helper: resolve or use cache ────────────────────────────────────────


# ── MCP Introspection Tools ─────────────────────────────────────────────


# ── MCP Agentic Tools ───────────────────────────────────────────────────


# ── Ephemeral Fingerprint MCP Tools ─────────────────────────────────────


@mcp.prompt()
def domain_report(domain: str) -> str:
    """Generate a domain intelligence report.

    Use this to summarize public domain-control, email-routing, identity-response,
    and infrastructure indicators with their observation limits.
    """
    safe_domain = validate_domain(domain)
    return (
        f"Look up {safe_domain} using lookup_tenant with format='markdown'. "
        "Summarize only the role-scoped public observations and their limits."
    )


def _print_mcp_banner() -> None:
    """Write the MCP server startup banner to stderr.

    stderr is used deliberately: the stdio transport owns stdout for
    JSON-RPC message framing, and any bytes written to stdout before
    or during server execution will corrupt that framing. stderr is
    safe — MCP clients either display it or discard it, but never
    parse it.
    """
    import sys

    from recon_tool import __version__

    try:
        from recon_tool.fingerprints import load_fingerprints
        from recon_tool.signals import load_signals

        fp_count = len(load_fingerprints())
        sig_count = len(load_signals())
    except Exception:
        fp_count = 0
        sig_count = 0

    lines = [
        "=" * 80,
        f"recon MCP Server v{__version__}",
        "",
        "WARNING: This server runs with the privileges of the calling user.",
        "Treat connected AI agents as untrusted input.",
        "Start with manual approvals; only enable auto-approval for tools you",
        "deliberately trust. For production agent use, prefer an isolated",
        "workspace or container with filesystem and network restrictions.",
        "=" * 80,
        "",
        "Listening on stdio transport.",
        f"Loaded {fp_count} fingerprints, {sig_count} signals.",
        "",
        "Available tools (selected):",
        "  lookup_tenant               Full domain intelligence + tenant details",
        "  analyze_posture             Neutral posture observations (accepts --profile)",
        "  assess_exposure             Model-bound public-evidence index (0-100)",
        "  find_hardening_gaps         Categorized gaps + recommendations",
        "  simulate_hardening          What-if hardening simulation",
        "  compare_postures            Side-by-side posture comparison",
        "  chain_lookup                Recursive related-domain discovery",
        "  explain_signal              Signal trigger conditions + evidence",
        "  test_hypothesis             Evaluate a theory against cached data",
        "  cluster_verification_tokens Cluster domains by shared TXT tokens",
        "  get_infrastructure_clusters CT co-occurrence community report (v1.8)",
        "  export_graph                Raw CT co-occurrence graph + cluster map (v1.8)",
        "",
        "MCP server is running and waiting for tool calls from your AI client.",
        "Press Ctrl+C to stop.",
        "",
        "Tip: configure this in Claude Desktop, Cursor, or VS Code using the",
        "     instructions in docs/mcp.md",
        "",
    ]
    sys.stderr.write("\n".join(lines))
    sys.stderr.flush()


def _print_tty_misuse_panel() -> None:
    """Tell a human who launched the server in a terminal what to do instead.

    The MCP stdio transport expects JSON-RPC frames on stdin. When a human
    runs the server in a TTY and presses Enter, the loose newline reaches
    the JSON-RPC parser as ``'\\n'`` and surfaces as a Pydantic validation
    error — terrifying-looking, but not actually broken. This panel
    intercepts that case and explains the situation before any framing
    error has a chance to fire.
    """
    import sys

    lines = [
        "=" * 80,
        "recon MCP server — this is NOT an interactive REPL.",
        "=" * 80,
        "",
        "The server speaks JSON-RPC over stdio. It is meant to be launched",
        "by an MCP client (Claude Desktop, Claude Code, Cursor, VS Code,",
        "Windsurf, Kiro), not run by hand at a shell prompt.",
        "",
        "What to do:",
        "  • Configure your client to spawn `recon mcp` and let the client",
        "    drive the JSON-RPC handshake. Per-client scaffolds live under",
        "    the agents/ directory of the recon repo, and config snippets",
        "    are in the README and docs/mcp.md.",
        "  • Run `recon doctor` to verify your install is healthy.",
        "  • Run `recon <domain>` to use the CLI directly.",
        "",
        "Override (for debugging / piping JSON-RPC by hand):",
        "  set RECON_MCP_FORCE_STDIO=1 before launching, and the server",
        "  will start even with a TTY attached.",
        "",
        "=" * 80,
        "",
    ]
    sys.stderr.write("\n".join(lines))
    sys.stderr.flush()


def _stdin_is_tty() -> bool:
    """Return True if stdin looks like an interactive terminal.

    Wrapped in a helper so tests can monkeypatch it without poking at the
    real ``sys.stdin``.
    """
    import sys

    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        # Some embedded environments replace stdin with an object that
        # doesn't implement isatty(), close it outright (ValueError),
        # or hand back a handle in a state that makes the underlying
        # ioctl/GetFileType call fail (OSError). In every case the
        # right answer is "no human at the keyboard" — behave like a
        # client launched us and let the JSON-RPC loop run.
        return False


def _detect_cwd_shadow_install() -> str | None:
    """Return a non-None error message if the recon_tool package was
    loaded from a cwd-shadow path.

    Python's ``-m`` flag prepends the current working directory to
    ``sys.path`` before installed packages (on Python 3.10 — Python 3.11+
    supports ``PYTHONSAFEPATH=1`` / ``-P`` to disable this, which
    ``recon_tool.mcp_doctor`` and ``recon_tool.mcp_install`` now set
    when they spawn / persist the server launch command). A malicious
    workspace that contains ``recon_tool/server.py`` will, on Python 3.10
    or when ``PYTHONSAFEPATH`` is unset, shadow the installed package and
    execute the attacker's code rather than the legitimate install.

    This guard runs at server startup. If the loaded ``recon_tool``
    module's ``__file__`` resolves to a path under the current working
    directory AND that cwd does *not* look like the legitimate recon
    source repository, return an error message. The caller (``main()``)
    prints it and exits with a non-zero status before any tool
    handlers run.

    Legitimate development workflows (running ``python -m recon_tool.server``
    from the source repo) are preserved because the cwd check matches a
    real ``pyproject.toml`` whose ``name`` field is ``recon-tool``.

    Returns ``None`` when the install looks safe, or a human-readable
    error string when shadowing is detected.
    """
    from pathlib import Path

    import recon_tool  # the actually-imported package — what we want to verify

    try:
        pkg_dir = Path(recon_tool.__file__).resolve().parent
    except (AttributeError, OSError):
        # If we can't even resolve the package path, something is far
        # weirder than cwd-shadowing. Don't block startup on it.
        return None

    try:
        cwd = Path.cwd().resolve()
    except (OSError, ValueError):
        # No usable cwd → cwd-shadow attack cannot apply. Don't block.
        return None

    try:
        pkg_dir.relative_to(cwd)
    except ValueError:
        # Package directory is outside cwd. The cwd-prepend attack
        # cannot reach the package; safe.
        return None

    # Package is under cwd. Verify cwd looks like the legitimate
    # recon source checkout. Two signals — pyproject.toml exists at cwd
    # AND its ``[project] name`` is exactly ``recon-tool``. Both
    # required; an attacker who plants a fake pyproject.toml with the
    # right name has done enough work that they could plant arbitrary
    # files anyway, but the joint check raises the bar.
    pyproject = cwd / "pyproject.toml"
    if pyproject.is_file():
        try:
            content = pyproject.read_text(encoding="utf-8")
        except OSError:
            content = ""
        # Tolerate whitespace variations: ``name="recon-tool"``,
        # ``name = "recon-tool"``, etc. The literal substring covers
        # the common cases without pulling in a TOML parser.
        if 'name = "recon-tool"' in content or 'name="recon-tool"' in content:
            return None  # legitimate source checkout

    return (
        "recon mcp server: refusing to start — the recon_tool package "
        f"was loaded from {pkg_dir}, which is under the current working "
        f"directory ({cwd}). This is the cwd-shadow attack pattern "
        "audited in v1.9.3.4: Python's -m flag prepends cwd to sys.path "
        "on Python < 3.11 (and when PYTHONSAFEPATH is unset), so a "
        "malicious workspace containing a recon_tool/ directory would "
        "execute attacker code instead of the installed package.\n"
        "\n"
        "If you intended to run from a legitimate source checkout, the "
        "checkout's pyproject.toml at this directory does not have "
        '`name = "recon-tool"`. Either:\n'
        "  * Run from outside the workspace (cd to your home directory "
        "and re-invoke); or\n"
        "  * Set PYTHONSAFEPATH=1 in the environment (Python 3.11+); or\n"
        "  * Install recon-tool via pip and invoke it as `recon mcp`, "
        "not `python -m recon_tool.server`.\n"
    )


def main() -> None:
    """Run the MCP server with stdio transport.

    Prints a professional startup banner to stderr before
    handing control to the FastMCP loop, and handles Ctrl+C /
    CancelledError / BrokenPipe cleanly so the user sees
    ``"MCP server stopped"`` instead of a raw traceback. The stdio
    transport is still owned by stdout — the banner and shutdown
    message both go to stderr so JSON-RPC framing stays clean.

    When stdin is a TTY (a human running the server directly in a
    shell), prints a misuse panel and exits 0 instead of feeding the
    user's stray newlines into the JSON-RPC parser. Set the env var
    ``RECON_MCP_FORCE_STDIO=1`` to override.
    """
    import os
    import sys

    # Runtime guard against cwd-shadow installs. Runs BEFORE
    # the TTY check so an attacker cannot rely on stdin being non-TTY
    # to bypass the guard. Defense-in-depth on top of the
    # PYTHONSAFEPATH=1 and safe-cwd protections in mcp_doctor/install.
    shadow_error = _detect_cwd_shadow_install()
    if shadow_error is not None:
        sys.stderr.write(shadow_error)
        sys.stderr.flush()
        sys.exit(EXIT_VALIDATION)

    force_stdio_raw = os.environ.get("RECON_MCP_FORCE_STDIO", "").strip().lower()
    if _stdin_is_tty() and force_stdio_raw not in {"1", "true", "yes", "on"}:
        _print_tty_misuse_panel()
        return

    _print_mcp_banner()

    with _runtime_logging():
        try:
            mcp.run()
        except KeyboardInterrupt:
            sys.stderr.write("\nMCP server stopped.\n")
            sys.stderr.flush()
        except (BrokenPipeError, ConnectionResetError):
            # Client disconnected. This is a clean shutdown from the
            # stdio transport's perspective, not an error worth raising.
            sys.stderr.write("\nMCP client disconnected. Server stopped.\n")
            sys.stderr.flush()
        except Exception as exc:
            # Any other unexpected failure: retain one bounded line without
            # allowing exception text to control the terminal.
            sys.stderr.write(f"\nMCP server exited unexpectedly ({type(exc).__name__}): {_fatal_detail(exc)}\n")
            sys.stderr.flush()
            raise SystemExit(EXIT_ERROR) from exc


# ── Bayesian fusion MCP tools (v1.9, stable v2.0+) ─────────────────────


if __name__ == "__main__":
    main()
