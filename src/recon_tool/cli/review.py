"""CLI delivery surface for fresh single-namespace ReviewBundles."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

from recon_tool.cli.shared import fmt_exc, positive_finite_float
from recon_tool.exit_codes import EXIT_INTERNAL, EXIT_NO_DATA, EXIT_VALIDATION
from recon_tool.formatter import render_error

__all__ = ["review"]

logger = logging.getLogger("recon")

_UNEXPECTED_REVIEW_ERROR = "Review collection failed because of an internal error. Run recon doctor, then retry."


def _preflight_output(path: Path | None, *, force: bool) -> None:
    if path is None:
        return
    if not path.parent.is_dir():
        raise ValueError(f"Review bundle output directory does not exist: {path.parent}")
    exists = path.exists() or path.is_symlink()
    if path.exists() and not path.is_file():
        raise ValueError(f"Review bundle output must be a file path: {path}")
    if exists and not force:
        raise FileExistsError(f"Review bundle output already exists: {path}")


def _failure_exit_code(error_type: str) -> int:
    return EXIT_NO_DATA if error_type == "no_data" else EXIT_INTERNAL


def review(
    domain: Annotated[str, typer.Argument(help="Namespace to review at its registrable apex.")],
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write the ReviewBundle JSON here.")] = None,
    no_ct: bool = typer.Option(False, "--no-ct", help="Skip certificate-transparency providers."),
    timeout: float = typer.Option(
        120.0,
        "--timeout",
        "-t",
        help="Aggregate collection timeout in seconds.",
        callback=positive_finite_float,
    ),
    force: bool = typer.Option(False, "--force", help="Replace an existing output file."),
    json_output: bool = typer.Option(False, "--json", help="Emit the full ReviewBundle JSON."),
) -> None:
    """Collect once and compose a deterministic evidence-linked review."""
    from recon_tool.formatter.review import format_review_bundle_markdown
    from recon_tool.models import ReconLookupError
    from recon_tool.resolver import resolve_tenant
    from recon_tool.review_bundle import ReviewCollectionContext, build_review_bundle, build_review_error_bundle
    from recon_tool.review_input import normalize_review_coordinate
    from recon_tool.validator import validate_domain

    try:
        coordinate = normalize_review_coordinate(domain)
        validated = validate_domain(coordinate)
        _preflight_output(output, force=force)
    except (FileExistsError, ValueError) as exc:
        render_error(fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from exc

    async def _collect() -> tuple[dict[str, Any], int]:
        started_at = datetime.now(UTC)
        try:
            info, results = await resolve_tenant(
                validated,
                timeout=timeout,
                skip_ct=no_ct,
                active_probes=False,
            )
        except ReconLookupError as exc:
            ended_at = datetime.now(UTC)
            error_kind = "timeout" if exc.error_type == "timeout" else "lookup"
            bundle = build_review_error_bundle(
                coordinate,
                ReviewCollectionContext(
                    started_at=started_at,
                    ended_at=ended_at,
                    ct_enabled=not no_ct,
                    timeout_seconds=timeout,
                ),
                error_kind,
                (source for source, _detail in exc.source_errors),
            )
            return bundle, _failure_exit_code(exc.error_type)
        ended_at = datetime.now(UTC)
        bundle = build_review_bundle(
            info,
            results,
            coordinate,
            ReviewCollectionContext(
                started_at=started_at,
                ended_at=ended_at,
                ct_enabled=not no_ct,
                timeout_seconds=timeout,
            ),
        )
        return bundle, 0

    try:
        bundle, exit_code = asyncio.run(_collect())
    except Exception as exc:
        logger.exception("Unexpected error composing a ReviewBundle for %s", validated)
        render_error(_UNEXPECTED_REVIEW_ERROR)
        raise typer.Exit(code=EXIT_INTERNAL) from exc

    if output is not None:
        from recon_tool.review_bundle import write_review_bundle

        try:
            write_review_bundle(output, bundle, overwrite=force)
        except (FileExistsError, ValueError) as exc:
            render_error(fmt_exc(exc))
            raise typer.Exit(code=EXIT_VALIDATION) from exc
        except OSError as exc:
            render_error(fmt_exc(exc))
            raise typer.Exit(code=EXIT_INTERNAL) from exc

    if json_output:
        typer.echo(json.dumps(bundle, ensure_ascii=False, indent=2, allow_nan=False))
    else:
        typer.echo(format_review_bundle_markdown(bundle))
        if output is not None:
            typer.echo(f"\nReviewBundle JSON: {output.resolve()}")
    if exit_code:
        raise typer.Exit(code=exit_code)
