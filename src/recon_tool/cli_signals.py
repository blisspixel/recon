"""The `recon signals` Typer sub-app (list / search / show the signal catalog),
with its signal-render helpers. Split out of cli.py; registered on the main app
via `app.add_typer` there. Heavy dependencies are imported inline in the commands.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, NoReturn

import typer

from recon_tool.exit_codes import EXIT_VALIDATION
from recon_tool.formatter import get_console

signals_app = typer.Typer(help="Inspect the built-in signal catalog.")


@signals_app.command("list")
def signals_list(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category (substring)"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """List every built-in signal, grouped by category."""
    from recon_tool.signals import load_signals

    sigs = load_signals()
    if category:
        needle = category.lower()
        import re

        def _match_cat(cat: str) -> bool:
            cat_lower = cat.lower()
            if " " in needle:
                return needle in cat_lower
            return any(word.startswith(needle) for word in re.findall(r"[a-z0-9]+", cat_lower))

        sigs = tuple(s for s in sigs if _match_cat(s.category))

    if json_output:
        payload = [
            {
                "name": s.name,
                "category": s.category,
                "confidence": s.confidence,
                "candidate_count": len(s.candidates),
                "min_matches": s.min_matches,
                "description": s.description,
            }
            for s in sigs
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    if not sigs:
        console.print("  No signals match those filters.")
        return
    console.print()
    console.print(f"  [bold]{len(sigs)} signal{'s' if len(sigs) != 1 else ''}[/bold]")
    console.print()
    name_w = max(len(s.name) for s in sigs)
    for s in sorted(sigs, key=lambda x: (x.category, x.name)):
        console.print(f"    {s.name:<{name_w}s}  {s.category:<20s}  {s.confidence}")
    console.print()


@signals_app.command("search")
def signals_search(
    query: str = typer.Argument(
        ..., help="Search term — matched against signal name, category, description, and candidate slugs"
    ),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Search signals by name, category, description, or candidate slug.

    Case-insensitive substring. Useful for "which signals look at my
    new slug?" (``search <slug>``) and "what signals fire on email
    posture?" (``search email``).
    """
    from recon_tool.signals import load_signals

    sigs = load_signals()
    needle = query.lower().strip()
    if not needle:
        from recon_tool.formatter import render_error

        render_error("Empty search query.")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    ranked: list[tuple[int, Any]] = []
    for s in sigs:
        rank: int | None = None
        if needle in s.name.lower():
            rank = 0
        elif needle in s.category.lower():
            rank = 1
        elif any(needle in c.lower() for c in s.candidates):
            rank = 2
        elif needle in s.description.lower():
            rank = 3
        if rank is not None:
            ranked.append((rank, s))

    ranked.sort(key=lambda x: (x[0], x[1].name))
    matches = [s for _, s in ranked]

    if json_output:
        payload = [
            {
                "name": s.name,
                "category": s.category,
                "confidence": s.confidence,
                "candidate_count": len(s.candidates),
                "description": s.description,
            }
            for s in matches
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    if not matches:
        console.print(f"  No signals match {query!r}.")
        return
    console.print()
    console.print(f"  [bold]{len(matches)} match{'es' if len(matches) != 1 else ''} for {query!r}[/bold]")
    console.print()
    name_w = max(len(s.name) for s in matches)
    for s in matches:
        console.print(f"    {s.name:<{name_w}s}  {s.category:<20s}  {s.confidence}")
    console.print()


def _signal_show_payload(match: Any) -> dict[str, Any]:
    """Build the JSON payload for `signals show --json`."""
    return {
        "name": match.name,
        "category": match.category,
        "confidence": match.confidence,
        "description": match.description,
        "candidates": list(match.candidates),
        "min_matches": match.min_matches,
        "metadata_conditions": [{"field": m.field, "operator": m.operator, "value": m.value} for m in match.metadata],
        "contradicts": list(match.contradicts),
        "requires_signals": list(match.requires_signals),
        "expected_counterparts": list(match.expected_counterparts),
        "positive_when_absent": list(match.positive_when_absent),
        "explain": match.explain,
    }


def _render_signal_not_found(name: str, sigs: Sequence[Any]) -> NoReturn:
    """Render a not-found error with near-miss suggestions, then exit."""
    from recon_tool.formatter import render_error

    needle = name.lower()
    candidates = [s.name for s in sigs if needle in s.name.lower()][:5]
    render_error(f"No signal named {name!r}.")
    if candidates:
        get_console().print(f"  Did you mean: {', '.join(repr(c) for c in candidates)}?")
    raise typer.Exit(code=EXIT_VALIDATION) from None


def _render_signal_section(console: Any, header: str, items: Sequence[str]) -> None:
    """Print a blank line, a bold header, and one ``- item`` per entry.

    A no-op when ``items`` is empty, so callers stay branch-free.
    """
    if not items:
        return
    console.print()
    console.print(f"  [bold]{header}[/bold]")
    for item in items:
        console.print(f"    - {item}")


def _render_signal_detail(match: Any) -> None:
    """Print the full human-readable definition of a single signal."""
    console = get_console()
    console.print()
    console.print(f"  [bold]{match.name}[/bold]")
    console.print(f"    Category:    {match.category}")
    console.print(f"    Confidence:  {match.confidence}")
    if match.description:
        console.print(f"    Description: {match.description}")
    _render_signal_section(
        console,
        f"Candidate slugs ({len(match.candidates)}, min_matches={match.min_matches})",
        list(match.candidates),
    )
    if match.metadata:
        console.print()
        console.print("  [bold]Metadata conditions[/bold]")
        for m in match.metadata:
            console.print(f"    - {m.field} {m.operator} {m.value!r}")
    _render_signal_section(console, "Contradicts", list(match.contradicts))
    _render_signal_section(console, "Requires other signals", list(match.requires_signals))
    _render_signal_section(console, "Expected counterparts (absence engine)", list(match.expected_counterparts))
    _render_signal_section(
        console, "Positive-when-absent (hedged hardening observation)", list(match.positive_when_absent)
    )
    if match.explain:
        console.print()
        console.print(f"  [bold]Explain[/bold] {match.explain}")
    console.print()


@signals_app.command("show")
def signals_show(
    name: str = typer.Argument(..., help="Signal name (quote if it contains spaces)"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Show the full definition of a single signal."""
    from recon_tool.signals import load_signals

    sigs = load_signals()
    match = next((s for s in sigs if s.name == name), None)
    if match is None:
        _render_signal_not_found(name, sigs)

    if json_output:
        typer.echo(json.dumps(_signal_show_payload(match), indent=2))
        return

    _render_signal_detail(match)

