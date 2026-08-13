"""CLI commands for caller-owned observation capsules."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.markup import escape

from recon_tool.cli.shared import fmt_exc, positive_finite_float, raise_lookup_error
from recon_tool.exit_codes import EXIT_INTERNAL, EXIT_VALIDATION
from recon_tool.formatter import get_console, render_error

capsule_app = typer.Typer(
    help="Capture, replay, and compare caller-owned observation capsules.",
    no_args_is_help=True,
)

__all__ = ["capsule_app"]


def _default_output(domain: str) -> Path:
    return Path.cwd() / f"recon-{domain}-capsule.json"


def _load(path: Path) -> dict[str, Any]:
    from recon_tool.capsule import load_capsule

    try:
        return load_capsule(path)
    except (OSError, ValueError) as exc:
        render_error(fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from exc


@capsule_app.command("capture", short_help="Capture a local observation artifact.")
def capture(
    domain: str = typer.Argument(..., help="Domain to collect at its registrable apex."),
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Capsule JSON path.")] = None,
    no_ct: bool = typer.Option(False, "--no-ct", help="Skip certificate-transparency providers."),
    direct_probes: bool = typer.Option(
        False,
        "--direct-probes",
        help="Opt in to Google CSE and BIMI certificate requests to target-owned hosts.",
    ),
    timeout: float = typer.Option(
        120.0,
        "--timeout",
        "-t",
        help="Aggregate collection timeout in seconds.",
        callback=positive_finite_float,
    ),
    vantage: str = typer.Option(
        "caller-local",
        "--vantage",
        help="Caller-chosen label for the resolver or collection vantage.",
    ),
    force: bool = typer.Option(False, "--force", help="Replace an existing output file."),
    json_output: bool = typer.Option(False, "--json", help="Emit the write receipt as JSON."),
) -> None:
    """Collect a domain and write a versioned, integrity-bound local capsule."""
    from recon_tool.capsule import CollectionContext, build_capsule, write_capsule
    from recon_tool.models import ReconLookupError
    from recon_tool.resolver import resolve_tenant
    from recon_tool.validator import validate_domain

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        render_error(fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from exc
    output_path = output or _default_output(validated)

    async def _capture() -> tuple[dict[str, Any], datetime, datetime]:
        started_at = datetime.now(UTC)
        info, results = await resolve_tenant(
            validated,
            timeout=timeout,
            skip_ct=no_ct,
            active_probes=direct_probes,
        )
        ended_at = datetime.now(UTC)
        capsule = build_capsule(
            info,
            results,
            CollectionContext(
                started_at=started_at,
                ended_at=ended_at,
                ct_enabled=not no_ct,
                direct_probes=direct_probes,
                timeout_seconds=timeout,
                vantage=vantage,
            ),
        )
        return capsule, started_at, ended_at

    try:
        capsule, _started_at, _ended_at = asyncio.run(_capture())
        write_capsule(output_path, capsule, overwrite=force)
    except ReconLookupError as exc:
        raise_lookup_error(exc, domain=validated)
    except (FileExistsError, ValueError) as exc:
        render_error(fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from exc
    except OSError as exc:
        render_error(fmt_exc(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from exc

    opportunities = capsule["source_opportunities"]
    receipt = {
        "record_type": "observation_capsule_write",
        "capsule_schema_version": capsule["capsule_schema_version"],
        "queried_domain": validated,
        "content_digest": capsule["content_digest"],
        "observation_count": len(capsule["observations"]),
        "source_role_count": len(opportunities),
        "path": str(output_path.resolve()),
    }
    if json_output:
        typer.echo(json.dumps(receipt, ensure_ascii=False, indent=2))
        return
    console = get_console()
    console.print("[bold]Observation capsule written[/bold]")
    console.print(f"  Domain       {escape(validated)}")
    console.print(f"  Observations {receipt['observation_count']} across {receipt['source_role_count']} source roles")
    console.print(f"  Digest       {escape(str(capsule['content_digest']))}")
    console.print(f"  File         {escape(str(output_path.resolve()))}")


@capsule_app.command("replay", short_help="Replay without network access.")
def replay(
    path: Annotated[Path, typer.Argument(help="Observation capsule JSON path.")],
    as_of: str | None = typer.Option(None, "--as-of", help="Explicit ISO 8601 evaluation time."),
    json_output: bool = typer.Option(False, "--json", help="Emit the replay record as JSON."),
) -> None:
    """Verify and replay a capsule through the current stable renderer."""
    from recon_tool.capsule import replay_capsule

    capsule = _load(path)
    try:
        result = replay_capsule(capsule, as_of=as_of)
    except ValueError as exc:
        render_error(fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from exc
    if json_output:
        typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
        return
    replayed = result["result"]
    console = get_console()
    console.print("[bold]Observation capsule replay[/bold]")
    console.print(f"  Domain         {escape(str(result['queried_domain']))}")
    console.print(f"  Evaluated as   {escape(str(result['evaluated_as_of']))}")
    console.print(f"  Context match  {'yes' if result['interpretation_context_match'] else 'no'}")
    console.print(f"  Provider       {escape(str(replayed.get('provider') or 'not observed'))}")
    console.print(f"  Confidence     {escape(str(replayed.get('confidence') or 'not observed'))}")
    console.print(f"  Services       {len(replayed.get('services', []))}")
    console.print("  Network calls  none")


def _change_count(section: Mapping[str, Any], field: str) -> int:
    value = section.get(field, [])
    return len(value) if isinstance(value, list) else 0


@capsule_app.command("compare", short_help="Classify two capsule deltas.")
def compare(
    before: Annotated[Path, typer.Argument(help="Earlier observation capsule.")],
    after: Annotated[Path, typer.Argument(help="Later observation capsule.")],
    before_as_of: str | None = typer.Option(None, "--before-as-of", help="Override the earlier evaluation time."),
    after_as_of: str | None = typer.Option(None, "--after-as-of", help="Override the later evaluation time."),
    json_output: bool = typer.Option(False, "--json", help="Emit the classified delta as JSON."),
) -> None:
    """Separate observation, collection, time, and interpretation changes."""
    from recon_tool.capsule import compare_capsules

    previous = _load(before)
    current = _load(after)
    try:
        result = compare_capsules(
            previous,
            current,
            before_as_of=before_as_of,
            after_as_of=after_as_of,
        )
    except ValueError as exc:
        render_error(fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from exc
    if json_output:
        typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
        return

    observation = result["observation"]
    collection = result["collection_regime"]
    time_evaluation = result["time_evaluation"]
    interpretation = result["interpretation"]
    console = get_console()
    console.print("[bold]Observation capsule comparison[/bold]")
    console.print(f"  Domain          {escape(str(result['queried_domain']))}")
    console.print(
        "  Observation     "
        f"{_change_count(observation, 'added')} added, "
        f"{_change_count(observation, 'removed')} removed, "
        f"{_change_count(observation, 'suppressed_source_roles')} source roles withheld"
    )
    console.print(f"  Collection      {_change_count(collection, 'changes')} regime changes")
    console.print(f"  Time evaluation {'changed' if time_evaluation['changed'] else 'unchanged'}")
    console.print(f"  Interpretation  {_change_count(interpretation, 'changes')} context or result changes")
