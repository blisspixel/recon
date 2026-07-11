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
    """List reportable public signals, grouped by category."""
    from recon_tool.signals import reportable_signals

    sigs = reportable_signals()
    if category:
        needle = category.lower()
        import re

        def _match_cat(cat: str) -> bool:
            cat_lower = cat.lower()
            if " " in needle:
                return needle in cat_lower
            return any(word.startswith(needle) for word in re.findall(r"[a-z0-9]+", cat_lower))

        sigs = tuple((signal, label) for signal, label in sigs if _match_cat(signal.category))

    if json_output:
        payload = [
            {
                "name": label,
                "category": signal.category,
                "confidence": signal.confidence,
                "candidate_count": len(signal.candidates),
                "min_matches": signal.min_matches,
                "description": signal.description,
            }
            for signal, label in sigs
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
    name_w = max(len(label) for _, label in sigs)
    for signal, label in sorted(sigs, key=lambda item: (item[0].category, item[1])):
        console.print(f"    {label:<{name_w}s}  {signal.category:<20s}  {signal.confidence}")
    console.print()


@signals_app.command("search")
def signals_search(
    query: str = typer.Argument(
        ..., help="Search term — matched against signal name, category, description, and candidate slugs"
    ),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Search reportable signals by label, category, description, or candidate slug.

    Case-insensitive substring. Useful for "which signals look at my
    new slug?" (``search <slug>``) and "what signals fire on email
    posture?" (``search email``).
    """
    from recon_tool.signals import reportable_signals

    sigs = reportable_signals()
    needle = query.lower().strip()
    if not needle:
        from recon_tool.formatter import render_error

        render_error("Empty search query.")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    ranked: list[tuple[int, Any]] = []
    for signal, label in sigs:
        rank: int | None = None
        if needle in label.lower():
            rank = 0
        elif needle in signal.category.lower():
            rank = 1
        elif any(needle in candidate.lower() for candidate in signal.candidates):
            rank = 2
        elif needle in signal.description.lower():
            rank = 3
        if rank is not None:
            ranked.append((rank, (signal, label)))

    ranked.sort(key=lambda item: (item[0], item[1][1]))
    matches = [item for _, item in ranked]

    if json_output:
        payload = [
            {
                "name": label,
                "category": signal.category,
                "confidence": signal.confidence,
                "candidate_count": len(signal.candidates),
                "description": signal.description,
            }
            for signal, label in matches
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
    name_w = max(len(label) for _, label in matches)
    for signal, label in matches:
        console.print(f"    {label:<{name_w}s}  {signal.category:<20s}  {signal.confidence}")
    console.print()


def _signal_show_payload(match: Any, public_label: str) -> dict[str, Any]:
    """Build the JSON payload for `signals show --json`."""
    from recon_tool.signals import public_signal_names

    return {
        "name": public_label,
        "category": match.category,
        "confidence": match.confidence,
        "description": match.description,
        "candidates": list(match.candidates),
        "min_matches": match.min_matches,
        "metadata_conditions": [{"field": m.field, "operator": m.operator, "value": m.value} for m in match.metadata],
        "contradicts": list(match.contradicts),
        "requires_signals": public_signal_names(match.requires_signals),
        "expected_counterparts": list(match.expected_counterparts),
        "positive_when_absent": list(match.positive_when_absent),
        "explain": match.explain,
    }


def _render_signal_not_found(name: str, labels: Sequence[str]) -> NoReturn:
    """Render a not-found error with near-miss suggestions, then exit."""
    from recon_tool.formatter import render_error

    needle = name.lower()
    candidates = [label for label in labels if needle in label.lower()][:5]
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


def _render_signal_detail(match: Any, public_label: str) -> None:
    """Print the full human-readable definition of a single signal."""
    from recon_tool.signals import public_signal_names

    console = get_console()
    console.print()
    console.print(f"  [bold]{public_label}[/bold]")
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
    _render_signal_section(console, "Requires other signals", public_signal_names(match.requires_signals))
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
    """Show the public definition of a single reportable signal."""
    from recon_tool.signals import reportable_signals, resolve_reportable_signal

    resolved = resolve_reportable_signal(name)
    if resolved is None:
        _render_signal_not_found(name, [label for _, label in reportable_signals()])
    match, public_label = resolved

    if json_output:
        typer.echo(json.dumps(_signal_show_payload(match, public_label), indent=2))
        return

    _render_signal_detail(match, public_label)
