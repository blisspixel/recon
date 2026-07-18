"""Doctor command implementation: environment/identity/CT/MCP/catalog checks.

Extracted from cli.py (docs/roadmap.md god-file track). Plain command-logic
helpers; the Typer app and the thin @app.command wrappers stay in cli.py, which
imports this module and references the orchestrators through a small assignment
facade. Imports the shared cli helpers / formatter; never imports cli.py.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Literal, TypeAlias

import typer

from recon_tool.cli.shared import fmt_exc as _fmt_exc
from recon_tool.cli.shared import render_diagnostic_status_row as _render_status_row
from recon_tool.cli.shared import safe_diagnostic_markup as _safe_markup
from recon_tool.exit_codes import (
    EXIT_ERROR,
    EXIT_NO_DATA,
    EXIT_VALIDATION,
)
from recon_tool.formatter import get_console

McpCheck: TypeAlias = tuple[str, bool, str]


DoctorStatus: TypeAlias = Literal["ok", "warn", "fail"]


DoctorCheck: TypeAlias = tuple[str, DoctorStatus, str]
TemplateCreateStatus: TypeAlias = Literal["created", "exists", "non_file"]


def _classify_template_collision(target: Path) -> TemplateCreateStatus | None:
    """Classify a publish collision without letting a probe mask the original error."""
    try:
        if not target.exists():
            return None
        return "exists" if target.is_file() else "non_file"
    except OSError:
        return None


def _create_template_atomically(target: Path, content: str) -> TemplateCreateStatus:
    """Publish a complete template without replacing any existing path.

    A same-directory hard link is the portable no-replace publication step.
    Filesystems without hard-link support fail safely instead of weakening the
    scaffold's no-overwrite guarantee.
    """
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        ) as stream:
            temp_path = Path(stream.name)
            stream.write(content)

        try:
            os.link(temp_path, target)
        except OSError:
            collision = _classify_template_collision(target)
            if collision is not None:
                return collision
            raise
        return "created"
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


_SIGNALS_TEMPLATE = """\
# Custom signals are merged with built-in signals at load time.
# Each entry defines a derived intelligence signal.
#
# Fields:
#   name:           Signal display name
#   category:       Signal category: security, identity, infrastructure, saas
#   confidence:     Signal confidence: high, medium, low
#   description:    Human-readable description (use hedged language for inferences)
#   requires:       List of fingerprint slugs required (all must match)
#   min_matches:    (optional) Minimum number of required slugs that must match
#   metadata:       (optional) Additional conditions on metadata fields
#     - field:      Metadata field: dmarc_policy, auth_type, email_security_score
#       operator:   Comparison: eq, neq, gte, lte
#       value:      Value to compare against
#
# Example:
# signals:
#   - name: "Custom Security Signal"
#     category: "security"
#     confidence: "medium"
#     description: "Custom security tooling indicators"
#     requires:
#       - "acme-sso"
#     min_matches: 1

signals: []
"""


_FINGERPRINTS_TEMPLATE = """\
# Custom fingerprints are merged with built-in fingerprints at load time.
# Each entry adds a new SaaS/service detection rule.
#
# Fields:
#   name:           Human-readable service name (shown in output)
#   slug:           Unique identifier (lowercase, hyphens)
#   type:           Detection type: txt, spf, mx, ns, cname, cname_target, subdomain_txt, caa, srv, dmarc_rua
#   pattern:        Regex pattern to match against DNS record value
#   category:       Service category: email, security, identity, saas, infrastructure
#   provider_group: (optional) Group for display: microsoft365, google-workspace
#   display_group:  (optional) Override display grouping
#
# Example:
# fingerprints:
#   - name: "Acme SSO"
#     slug: "acme-sso"
#     type: "txt"
#     pattern: "acme-domain-verification="
#     category: "identity"

fingerprints: []
"""


def _mcp_tool_registry_check(server_mcp: Any, required_tools: frozenset[str]) -> McpCheck:
    """Return the static canonical-tool registry check."""
    try:
        tools = asyncio.run(server_mcp.list_tools())
        tool_names = {str(getattr(tool, "name", "")) for tool in tools}
        missing_tools = sorted(required_tools - tool_names)
        if missing_tools:
            return (
                "Tools enumerated",
                False,
                f"{len(tools)} registered; missing canonical: {', '.join(missing_tools)}",
            )
        return (
            "Tools enumerated",
            True,
            f"{len(tools)} registered; {len(required_tools)} canonical tools present",
        )
    except Exception as exc:
        return ("Tools enumerated", False, f"{exc}")


def _mcp_resource_registry_check(server_mcp: Any, required_resources: tuple[str, ...]) -> McpCheck:
    """Return the static canonical-resource registry check."""
    try:
        resources = asyncio.run(server_mcp.list_resources())
        resource_uris = {str(getattr(resource, "uri", "")) for resource in resources}
        missing_resources = [uri for uri in required_resources if uri not in resource_uris]
        if missing_resources:
            return (
                "Resources enumerated",
                False,
                f"{len(resources)} registered; missing canonical: {', '.join(missing_resources)}",
            )
        return (
            "Resources enumerated",
            True,
            f"{len(resources)} registered; {len(required_resources)} canonical resources present",
        )
    except Exception as exc:
        return ("Resources enumerated", False, f"{exc}")


def _render_mcp_reference_config() -> None:
    """Render the generic config and safe-installer guidance."""
    from recon_tool.mcp_client.install import build_recon_block, warn_if_fallback

    console = get_console()
    recon_block = build_recon_block()
    console.print()
    console.print(
        "  [yellow]Security note:[/yellow] `recon mcp` runs with the privileges of\n"
        "  the calling user. Start with manual approvals and only expand\n"
        "  `autoApprove` if you fully understand the risk."
    )
    console.print()
    console.print("  [bold]Reference config for clients that use `mcpServers`[/bold]")
    console.print()
    console.print("  [dim]# Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json[/dim]")
    console.print("  [dim]# Cursor: ~/.cursor/mcp.json or <project>/.cursor/mcp.json[/dim]")
    console.print("  [dim]# Windsurf: ~/.codeium/windsurf/mcp_config.json[/dim]")
    console.print("  [dim]# Kiro: ~/.kiro/settings/mcp.json or <project>/.kiro/settings/mcp.json[/dim]")
    console.print(
        "  [dim]# VS Code uses a different top-level `servers` key; run `recon mcp install --client=vscode`.[/dim]"
    )
    console.print(
        "  [dim]# Prefer `recon mcp install --client=<name>` so existing client configuration is merged safely.[/dim]"
    )
    console.print()
    typer.echo(json.dumps({"mcpServers": {"recon": recon_block}}, indent=2))
    console.print()

    if warn_if_fallback() is not None:
        console.print(
            "  [yellow]Tip:[/yellow] GUI clients (Claude Desktop, Windsurf) often don't\n"
            "  inherit your shell PATH. The config above uses recon's safe\n"
            "  sys.path-stripping Python fallback. For a shorter config, add\n"
            "  `recon` to PATH and rerun `recon doctor --mcp`."
        )
        console.print()


def doctor_mcp() -> None:
    """Validate the static MCP registry and emit copy-pasteable client config."""
    import shutil
    import sys

    console = get_console()
    console.print()

    checks: list[McpCheck] = []

    # 1. MCP package importable
    import importlib

    try:
        importlib.import_module("mcp")
        from recon_tool.mcp_client.sdk_compat import SDK_FAMILY, SDK_VERSION

        checks.append(("MCP package", True, f"mcp {SDK_VERSION} ({SDK_FAMILY}) installed"))
    except ImportError as exc:
        checks.append(("MCP package", False, f"not installed: {exc}"))
        checks.append(("Install hint", False, "pip install -U recon-tool"))
        _render_mcp_checks(checks)
        raise typer.Exit(code=EXIT_ERROR) from exc

    # 2. Server module imports cleanly
    try:
        from recon_tool.server import mcp as server_mcp

        checks.append(("Server module", True, "loaded"))
    except Exception as exc:
        checks.append(("Server module", False, f"import failed: {exc}"))
        _render_mcp_checks(checks)
        raise typer.Exit(code=EXIT_ERROR) from exc

    # 3. MCP server has instructions
    instructions = getattr(server_mcp, "instructions", None)
    if isinstance(instructions, str) and instructions.strip():
        checks.append(("Server Instructions", True, f"{len(instructions)} chars"))
    else:
        checks.append(("Server Instructions", False, "missing; agents may misuse tools"))

    # 4. Enumerate tools through the public SDK surface and require the
    # canonical workflow anchors. Extra registered tools remain compatible.
    from recon_tool.mcp_client.doctor import REQUIRED_RESOURCES, REQUIRED_TOOLS

    checks.append(_mcp_tool_registry_check(server_mcp, REQUIRED_TOOLS))

    # 5. Enumerate local resources independently so a tool-list failure does
    # not hide a second registration problem.
    checks.append(_mcp_resource_registry_check(server_mcp, REQUIRED_RESOURCES))

    # 6. recon executable on PATH (important for short GUI-client configs)
    recon_path = shutil.which("recon")
    if recon_path:
        checks.append(("recon on PATH", True, recon_path))
    else:
        checks.append(("recon on PATH", True, f"not found; generated config will use {sys.executable} fallback"))

    _render_mcp_checks(checks)

    # Keep the reference config in sync with the safe installer.
    _render_mcp_reference_config()

    if not all(ok for _name, ok, _detail in checks):
        raise typer.Exit(code=EXIT_ERROR)


def _render_mcp_checks(checks: list[tuple[str, bool, str]]) -> None:
    """Render MCP check results with ok/FAIL labels."""
    console = get_console()
    for name, ok, detail in checks:
        mark = "ok" if ok else "FAIL"
        style = "green" if ok else "red"
        _render_status_row(console, mark=mark, style=style, name=name, detail=detail)


def doctor_client(client: str) -> None:
    """Read a client's MCP config and report whether recon is registered.

    Complements `--mcp` (which validates the server) by answering the
    other half of "did the install work": does the client's own config
    file carry the recon server entry that client would load.
    """
    from recon_tool.mcp_client.client_doctor import ClientCheck, check_client
    from recon_tool.mcp_client.install import SUPPORTED_CLIENTS

    console = get_console()
    console.print()

    if client not in SUPPORTED_CLIENTS:
        console.print(
            f"  [red]unknown client '{_safe_markup(client)}'[/red]\n  Supported: {', '.join(SUPPORTED_CLIENTS)}"
        )
        raise typer.Exit(EXIT_VALIDATION)

    report = check_client(client)  # pyright: ignore[reportArgumentType]
    console.print(f"  [bold]MCP client config check: {_safe_markup(client)}[/bold]")
    console.print()

    _style = {"ok": "green", "warn": "yellow", "fail": "red", "info": "dim"}
    _mark = {"ok": "ok", "warn": "warn", "fail": "FAIL", "info": "·"}
    check: ClientCheck
    for check in report.checks:
        style = _style[check.status]
        mark = _mark[check.status]
        console.print(f"  [{style}]{mark:>4}[/{style}]  {_safe_markup(check.name)}: {_safe_markup(check.detail)}")

    if report.notes:
        console.print()
        for note in report.notes:
            console.print(f"  [dim]note:[/dim] {_safe_markup(note)}")

    console.print()
    if report.ok:
        console.print("  [green]recon is registered in this client's config.[/green]")
        console.print()
        return
    console.print(
        f"  [yellow]recon was not found (or a config file is broken).[/yellow] "
        f"See the notes above, or run `recon mcp install --client={client}`."
    )
    console.print()
    raise typer.Exit(EXIT_NO_DATA)


def doctor_fix() -> bool:
    """Scaffold template config files and report whether every write succeeded."""

    from recon_tool.paths import config_dir as _config_dir

    console = get_console()
    config_dir = _config_dir()

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.print(f"[red]Cannot create config directory {_safe_markup(config_dir)}: {_safe_markup(exc)}[/red]")
        return False

    templates = [
        ("fingerprints.yaml", _FINGERPRINTS_TEMPLATE),
        ("signals.yaml", _SIGNALS_TEMPLATE),
    ]

    failures = 0
    for filename, content in templates:
        target = config_dir / filename
        try:
            status = _create_template_atomically(target, content)
            if status == "created":
                console.print(f"  [green]created:[/green] {_safe_markup(target)}")
            elif status == "exists":
                console.print(f"  already exists: {_safe_markup(target)}")
            else:
                failures += 1
                console.print(f"  [red]cannot use {_safe_markup(target)}: path is not a regular file[/red]")
        except OSError as exc:
            failures += 1
            console.print(f"  [red]failed to create {_safe_markup(target)}: {_safe_markup(exc)}[/red]")

    if failures:
        noun = "template" if failures == 1 else "templates"
        console.print(f"  [red]{failures} {noun} could not be created.[/red]")
        return False
    return True


def _doctor_print_header(console: Any) -> None:
    """Print the version line with the schema-stability indicator, plus Python.

    The substring "v2.0 stable schema" (vs "pre-v2.0 schema") lets an
    operator see at a glance whether Bayesian fusion is opt-in (pre-v2.0) or
    stable per the schema-lock disposition table; the v2.0 quality bar requires
    that text.
    """
    from recon_tool import __version__

    console.print()
    schema_label = "v2.0 stable schema" if __version__.startswith("2.") else "pre-v2.0 schema"
    console.print(f"  recon [bold]v{__version__}[/bold] [dim]({schema_label})[/dim]")
    console.print(f"  Python [bold]{sys.version.split()[0]}[/bold]")
    console.print()


async def _doctor_identity_checks() -> list[DoctorCheck]:
    """Probe the Microsoft identity-discovery endpoints (OIDC, GetUserRealm, Autodiscover)."""
    import httpx

    checks: list[DoctorCheck] = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get("https://login.microsoftonline.com/common/.well-known/openid-configuration")
            checks.append(("OIDC discovery", "ok" if resp.status_code == 200 else "fail", f"HTTP {resp.status_code}"))
        except (httpx.RequestError, OSError) as exc:
            checks.append(("OIDC discovery", "fail", _fmt_exc(exc)))

        # Synthetic non-existent address avoids probing a real account.
        try:
            resp = await client.get(
                "https://login.microsoftonline.com/GetUserRealm.srf",
                params={"login": "recon-connectivity-check@example.com", "json": "1"},
            )
            checks.append(("GetUserRealm", "ok" if resp.status_code == 200 else "fail", f"HTTP {resp.status_code}"))
        except (httpx.RequestError, OSError) as exc:
            checks.append(("GetUserRealm", "fail", _fmt_exc(exc)))

        try:
            resp = await client.post(
                "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
                content="<test/>",
                headers={"Content-Type": "text/xml"},
            )
            checks.append(("Autodiscover", "ok", f"HTTP {resp.status_code} (reachable)"))
        except (httpx.RequestError, OSError) as exc:
            checks.append(("Autodiscover", "fail", _fmt_exc(exc)))
    return checks


def _doctor_dns_check() -> DoctorCheck:
    """Resolve a known-good TXT record to confirm DNS works."""
    import dns.exception
    import dns.resolver

    try:
        answers = dns.resolver.resolve("example.com", "TXT")
        return ("DNS resolution", "ok", f"{len(list(answers))} TXT records")  # pyright: ignore[reportArgumentType]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        OSError,
    ) as exc:
        return ("DNS resolution", "fail", _fmt_exc(exc))


async def _doctor_ct_check() -> DoctorCheck:
    """Check crt.sh connectivity (certificate transparency, optional enrichment)."""
    import httpx

    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            resp = await client.get("https://crt.sh/?q=%.example.com&output=json")
            if resp.status_code == 200:
                return ("crt.sh (cert transparency)", "ok", "HTTP 200")
            return (
                "crt.sh (cert transparency)",
                "warn",
                f"HTTP {resp.status_code} (optional enrichment degraded)",
            )
        except (httpx.RequestError, OSError) as exc:
            return ("crt.sh (cert transparency)", "warn", f"{_fmt_exc(exc)} (optional enrichment degraded)")


def _doctor_mcp_check() -> DoctorCheck:
    """Confirm the MCP server module imports cleanly."""
    try:
        from recon_tool.server import mcp  # noqa: F401  # pyright: ignore[reportUnusedImport]

        return ("MCP server module", "ok", "loaded")
    except Exception as exc:
        return ("MCP server module", "fail", _fmt_exc(exc))


def _doctor_fingerprint_db_check() -> DoctorCheck:
    """Confirm the built-in fingerprint database loads."""
    try:
        from recon_tool.fingerprints import load_fingerprints

        fps = load_fingerprints()
        if fps:
            return ("Fingerprint database", "ok", f"{len(fps)} fingerprints loaded")
        return ("Fingerprint database", "fail", "no fingerprints loaded; detection will not work")
    except Exception as exc:
        return ("Fingerprint database", "fail", _fmt_exc(exc))


def _doctor_custom_path(filename: str) -> Path:
    """Resolve a custom config file path in the config dir (env / legacy / XDG)."""
    from recon_tool.paths import config_dir

    return config_dir() / filename


def _doctor_custom_fingerprints_check() -> DoctorCheck:
    """Report on the optional user fingerprints.yaml overlay."""
    custom_path = _doctor_custom_path("fingerprints.yaml")
    if not custom_path.exists():
        return ("Custom fingerprints", "ok", f"none ({custom_path} not found)")
    try:
        import yaml

        data = yaml.safe_load(custom_path.read_text(encoding="utf-8"))
        count = 0
        if isinstance(data, dict) and "fingerprints" in data:
            count = len(data["fingerprints"])
        elif isinstance(data, list):
            count = len(data)
        return ("Custom fingerprints", "ok", f"{count} entries in {custom_path}")
    except Exception as exc:
        return ("Custom fingerprints", "fail", _fmt_exc(exc))


def _doctor_signal_db_check() -> DoctorCheck:
    """Confirm the built-in signal database loads."""
    try:
        from recon_tool.signals import load_signals

        sigs = load_signals()
        if sigs:
            return ("Signal database", "ok", f"{len(sigs)} signals loaded")
        return ("Signal database", "fail", "no signals loaded; signal intelligence will not work")
    except Exception as exc:
        return ("Signal database", "fail", _fmt_exc(exc))


def _doctor_schema_fields_check() -> DoctorCheck:
    """Verify the locked-schema top-level fields are still emitted by ``format_tenant_json``.

    The v2.0 quality bar: synthesise a minimal TenantInfo, render it
    through the JSON formatter, and confirm every required top-level field from
    ``recon_tool.schema_contract.REQUIRED_TOP_LEVEL_FIELDS`` appears. Drift
    between that tuple and ``docs/recon-schema.json#/required`` is caught at PR
    time by ``tests/test_json_schema_file.py``.
    """
    try:
        import json as _json

        from recon_tool.formatter import format_tenant_json
        from recon_tool.models import ConfidenceLevel, TenantInfo
        from recon_tool.schema_contract import REQUIRED_TOP_LEVEL_FIELDS

        sample = TenantInfo(
            tenant_id="recon-doctor-sample",
            display_name="recon doctor synthetic",
            default_domain="example.invalid",
            queried_domain="example.invalid",
            confidence=ConfidenceLevel.LOW,
        )
        payload = _json.loads(format_tenant_json(sample))
        missing = sorted(set(REQUIRED_TOP_LEVEL_FIELDS) - set(payload.keys()))
        if missing:
            return ("Schema fields", "fail", f"{len(missing)} locked field(s) missing from emitter output: {missing}")
        return ("Schema fields", "ok", f"{len(REQUIRED_TOP_LEVEL_FIELDS)} locked top-level fields present")
    except Exception as exc:
        return ("Schema fields", "fail", _fmt_exc(exc))


def _doctor_custom_signals_check() -> DoctorCheck:
    """Report on the optional user signals.yaml overlay."""
    custom_signals_path = _doctor_custom_path("signals.yaml")
    if not custom_signals_path.exists():
        return ("Custom signals", "ok", f"none ({custom_signals_path} not found)")
    try:
        import yaml as _yaml

        data = _yaml.safe_load(custom_signals_path.read_text(encoding="utf-8"))
        count = 0
        if isinstance(data, dict) and "signals" in data:
            count = len(data["signals"])
        return ("Custom signals", "ok", f"{count} entries in {custom_signals_path}")
    except Exception as exc:
        return ("Custom signals", "fail", _fmt_exc(exc))


def _doctor_render(console: Any, checks: list[DoctorCheck]) -> bool:
    """Print each check row and the closing summary line.

    Returns True when any check failed, so the caller can set a non-zero
    process exit code for scriptable health gating.
    """
    has_failures = False
    has_warnings = False
    for name, status, detail in checks:
        mark = {"ok": "ok", "warn": "WARN", "fail": "FAIL"}[status]
        style = {"ok": "green", "warn": "yellow", "fail": "red"}[status]
        safe_name = _safe_markup(name)
        safe_detail = _safe_markup(detail)
        console.print(f"  [{style}]{mark:>4}[/{style}]  {safe_name}: {safe_detail}")
        if status == "fail":
            has_failures = True
        elif status == "warn":
            has_warnings = True

    console.print()
    if has_failures:
        console.print("  [yellow]Some checks failed. Lookups may be incomplete.[/yellow]")
    elif has_warnings:
        console.print("  [yellow]Core checks passed. Optional enrichment sources are degraded.[/yellow]")
    else:
        console.print("  [green]All checks passed.[/green]")
    console.print()
    return has_failures


async def doctor() -> None:
    """Run diagnostic checks.

    The check order is load-bearing: ``tests/test_doctor.py`` drives the
    httpx mock with a positional side-effect list, so identity probes must
    run before the crt.sh probe.

    Exit code is 0 when every check passes or only optional enrichment is
    degraded (warnings), and 1 when any core check fails, so a CI or
    monitoring job can gate on ``recon doctor`` instead of always reading
    success.
    """
    console = get_console()
    _doctor_print_header(console)

    checks: list[DoctorCheck] = []
    checks.extend(await _doctor_identity_checks())
    checks.append(_doctor_dns_check())
    checks.append(await _doctor_ct_check())
    checks.append(_doctor_mcp_check())
    checks.append(_doctor_fingerprint_db_check())
    checks.append(_doctor_custom_fingerprints_check())
    checks.append(_doctor_signal_db_check())
    checks.append(_doctor_schema_fields_check())
    checks.append(_doctor_custom_signals_check())

    if _doctor_render(console, checks):
        raise typer.Exit(code=EXIT_ERROR)
