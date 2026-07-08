"""The `recon fingerprints` Typer sub-app (list / search / show / check / new /
test the fingerprint catalog). Split out of cli.py; registered on the main app
via `app.add_typer` there. Heavy dependencies are imported inline in the
commands; the shared exception formatter comes from cli_shared.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.markup import escape

from recon_tool.cli.shared import fmt_exc as _fmt_exc
from recon_tool.exit_codes import EXIT_VALIDATION
from recon_tool.formatter import get_console, get_err_console
from recon_tool.validator import strip_control_chars

fingerprints_app = typer.Typer(help="Inspect the built-in fingerprint catalog.")


def _find_example_corpus_path() -> Path | None:
    for root in (Path.cwd(), *Path(__file__).resolve().parents):
        candidate = root / "tests" / "fixtures" / "corpus-example.txt"
        if candidate.exists():
            return candidate
    return None


@fingerprints_app.command("list")
def fingerprints_list(
    category: str | None = typer.Option(
        None, "--category", "-c", help="Filter by category (substring, case-insensitive)"
    ),
    detection_type: str | None = typer.Option(
        None,
        "--type",
        "-t",
        help="Filter by detection type (txt, mx, spf, cname, srv, caa, ns, subdomain_txt, dkim)",
    ),
    all_entries: bool = typer.Option(False, "--all", "-a", help="Print the full table even with no filters"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """List built-in fingerprints.

    With no filters, shows a per-category summary — the full catalog is
    too much to dump at a prompt. Use ``--category`` to scope to one
    file (e.g. ``-c ai``, ``-c security``) or ``--all`` to force the
    full table. For free-text lookups (slug / name / pattern), prefer
    ``recon fingerprints search <query>``.
    """
    from recon_tool.fingerprints import load_fingerprints

    fps = load_fingerprints()
    had_filter = category is not None or detection_type is not None
    if category:
        needle = category.lower()

        # Word-prefix matching instead of raw substring — ``-c ai`` should
        # match "AI & Generative" but not "Email" (which contains the
        # substring ``ai``). Split the category into alpha-word tokens
        # and match against the start of each token. Falls back to a
        # full substring match for multi-word queries (``-c "data &"``).
        def _match(cat: str) -> bool:
            cat_lower = cat.lower()
            if " " in needle:
                return needle in cat_lower
            import re

            return any(word.startswith(needle) for word in re.findall(r"[a-z0-9]+", cat_lower))

        fps = tuple(fp for fp in fps if _match(fp.category))
    if detection_type:
        dtype = detection_type.lower()
        fps = tuple(fp for fp in fps if any(d.type.lower() == dtype for d in fp.detections))

    if json_output:
        payload = [
            {
                "slug": fp.slug,
                "name": fp.name,
                "category": fp.category,
                "confidence": fp.confidence,
                "detection_types": sorted({d.type for d in fp.detections}),
                "detection_count": len(fp.detections),
            }
            for fp in fps
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    if not fps:
        console.print("  No fingerprints match those filters.")
        return

    # Compact summary when the user asked for the full catalog. A table
    # with hundreds of rows is not a useful answer to "what's in here". A
    # category breakdown with counts plus a filter hint is.
    if not had_filter and not all_entries:
        from collections import Counter

        by_cat = Counter(fp.category for fp in fps)
        console.print()
        console.print(f"  [bold]{len(fps)} fingerprints across {len(by_cat)} categories[/bold]")
        console.print()
        width = max(len(cat) for cat in by_cat)
        for cat, n in sorted(by_cat.items(), key=lambda x: (-x[1], x[0])):
            console.print(f"    {cat:<{width}s}  {n:>4d}")
        console.print()
        console.print(
            "  [dim]Next:[/dim]  recon fingerprints list --category <name>     "
            "recon fingerprints search <query>     recon fingerprints show <slug>"
        )
        console.print()
        return

    console.print()
    console.print(f"  [bold]{len(fps)} fingerprint{'s' if len(fps) != 1 else ''}[/bold]")
    console.print()
    slug_w = max(len(fp.slug) for fp in fps)
    cat_w = max(len(fp.category) for fp in fps)
    for fp in sorted(fps, key=lambda f: (f.category, f.slug)):
        types = ",".join(sorted({d.type for d in fp.detections}))
        console.print(f"    {fp.slug:<{slug_w}s}  {fp.category:<{cat_w}s}  {types:<18s}  {fp.name}")
    console.print()


@fingerprints_app.command("search")
def fingerprints_search(
    query: str = typer.Argument(..., help="Search term — matched against slug, name, category, and detection patterns"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Search fingerprints by slug, name, category, or detection pattern.

    Case-insensitive substring across four fields simultaneously —
    the primary discovery command for "does this exist" / "what does
    recon know about X". Results are ranked: slug-prefix matches
    first, then slug/name substring matches, then pattern matches.

    Examples::

        recon fingerprints search okta          # slug + name hits
        recon fingerprints search "verification" # matches all *-verification= TXT tokens
        recon fingerprints search pardot         # what slug does Pardot live under
    """
    from recon_tool.fingerprints import load_fingerprints

    fps = load_fingerprints()
    needle = query.lower().strip()
    if not needle:
        from recon_tool.formatter import render_error

        render_error("Empty search query.")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # Rank each fingerprint by how strong the match is. Slug-prefix is
    # the strongest signal ("they know exactly what they're looking
    # for"); a hit only in a detection pattern is weakest. We don't use
    # fuzzy matching — substring is enough for the built-in catalog
    # and doesn't pull in a dependency.
    ranked: list[tuple[int, Any]] = []
    for fp in fps:
        rank: int | None = None
        if fp.slug.lower().startswith(needle):
            rank = 0
        elif needle in fp.slug.lower():
            rank = 1
        elif needle in fp.name.lower():
            rank = 2
        elif needle in fp.category.lower():
            rank = 3
        else:
            for d in fp.detections:
                if needle in d.pattern.lower() or needle in d.description.lower():
                    rank = 4
                    break
        if rank is not None:
            ranked.append((rank, fp))

    ranked.sort(key=lambda x: (x[0], x[1].slug))
    matches = [fp for _, fp in ranked]

    if json_output:
        payload = [
            {
                "slug": fp.slug,
                "name": fp.name,
                "category": fp.category,
                "confidence": fp.confidence,
                "detection_types": sorted({d.type for d in fp.detections}),
                "detection_count": len(fp.detections),
            }
            for fp in matches
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    if not matches:
        console.print(f"  No fingerprints match {query!r}.")
        console.print("  [dim]Try a shorter or differently-spelled query, or browse by category:[/dim]")
        console.print("  [dim]  recon fingerprints list[/dim]")
        return

    console.print()
    console.print(f"  [bold]{len(matches)} match{'es' if len(matches) != 1 else ''} for {query!r}[/bold]")
    console.print()
    slug_w = max(len(fp.slug) for fp in matches)
    cat_w = max(len(fp.category) for fp in matches)
    for fp in matches:
        types = ",".join(sorted({d.type for d in fp.detections}))
        console.print(f"    {fp.slug:<{slug_w}s}  {fp.category:<{cat_w}s}  {types:<18s}  {fp.name}")
    console.print()
    console.print("  [dim]Next:[/dim]  recon fingerprints show <slug>")
    console.print()


@fingerprints_app.command("show")
def fingerprints_show(
    slug: str = typer.Argument(..., help="Slug to inspect (e.g. `cloudflare`, `exchange-onprem`)"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Show the full definition of a single fingerprint.

    Some slugs in recon output are *synthetic* — they're emitted by the
    source layer rather than loaded from YAML (e.g. ``exchange-onprem``
    from the OWA/autodiscover probe, ``self-hosted-mail`` from the MX
    fallback). Those are documented here too so users who see a slug
    in their output can always find its provenance.
    """
    # Synthetic slugs aren't in fingerprints.yaml — they're emitted
    # by source-layer probes. Document provenance so users aren't left
    # grepping the code.
    _SYNTHETIC_SLUGS: dict[str, tuple[str, str]] = {
        "exchange-onprem": (
            "Exchange Server (on-prem / hybrid)",
            "Emitted by recon_tool.sources.dns._detect_exchange_onprem when "
            "owa./outlook./exchange./mail-ex./autodiscover. subdomains resolve "
            "(wildcard-guarded). Indicates self-hosted or hybrid Exchange — "
            "not Exchange Online.",
        ),
        "self-hosted-mail": (
            "Self-hosted mail",
            "Emitted by recon_tool.sources.dns._detect_mx when MX records "
            "exist and no known cloud-provider or gateway fingerprint matched. "
            "The raw_value field carries the actual MX hosts so the user can "
            "see the underlying infrastructure.",
        ),
    }

    from recon_tool.fingerprints import load_fingerprints

    fps = load_fingerprints()
    match = next((fp for fp in fps if fp.slug == slug), None)
    if match is None and slug in _SYNTHETIC_SLUGS:
        name, note = _SYNTHETIC_SLUGS[slug]
        if json_output:
            typer.echo(json.dumps({"slug": slug, "name": name, "synthetic": True, "note": note}, indent=2))
            return
        console = get_console()
        console.print()
        console.print(f"  [bold]{name}[/bold]  ({slug})")
        console.print("    [dim]synthetic slug — emitted by source probe, not in fingerprints.yaml[/dim]")
        console.print()
        console.print(f"  {note}")
        console.print()
        return
    if match is None:
        from recon_tool.formatter import render_error

        candidates = [fp.slug for fp in fps if slug.lower() in fp.slug.lower()][:5]
        render_error(f"No fingerprint with slug {slug!r}.")
        if candidates:
            get_console().print(f"  Did you mean: {', '.join(candidates)}?")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    if json_output:
        payload = {
            "slug": match.slug,
            "name": match.name,
            "category": match.category,
            "confidence": match.confidence,
            "m365": match.m365,
            "provider_group": match.provider_group,
            "display_group": match.display_group,
            "match_mode": match.match_mode,
            "detections": [
                {
                    "type": d.type,
                    "pattern": d.pattern,
                    "description": d.description,
                    "reference": d.reference,
                    "weight": d.weight,
                }
                for d in match.detections
            ],
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    console.print()
    console.print(f"  [bold]{match.name}[/bold]  ({match.slug})")
    console.print(f"    Category:    {match.category}")
    console.print(f"    Confidence:  {match.confidence}")
    if match.m365:
        console.print("    M365 tenant: yes")
    if match.provider_group:
        console.print(f"    Provider group: {match.provider_group}")
    if match.match_mode != "any":
        console.print(f"    Match mode:  {match.match_mode} (all rules must match)")
    console.print()
    console.print(f"  [bold]Detection rules ({len(match.detections)})[/bold]")
    for i, d in enumerate(match.detections, 1):
        console.print(f"    {i}. [{d.type}] {d.pattern}")
        if d.description:
            console.print(f"         {d.description}")
        if d.reference:
            console.print(f"         ref: [link={d.reference}]{escape(d.reference)}[/link]")
    console.print()


@fingerprints_app.command("new")
def fingerprints_new(
    slug: str = typer.Argument(..., help="Unique slug for the new fingerprint (lowercase, hyphen-separated)"),
    name: str = typer.Option(..., "--name", "-n", help="Human-readable service name (e.g. 'Acme Security')"),
    category: str = typer.Option(
        "Misc",
        "--category",
        "-c",
        help="Category — must match an existing one (use `fingerprints list` to see options)",
    ),
    detection_type: str = typer.Option(
        "txt",
        "--type",
        "-t",
        help="Detection type: txt, spf, mx, cname, srv, caa, ns, subdomain_txt, dmarc_rua",
    ),
    pattern: str = typer.Option(..., "--pattern", "-p", help="Regex pattern to match"),
    description: str = typer.Option("", "--description", help="One-line description of what this record means"),
    reference: str = typer.Option("", "--reference", help="URL to the vendor's verification docs"),
    confidence: str = typer.Option("high", "--confidence", help="high, medium, or low"),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Write YAML to this file (default: print to stdout)"
    ),
) -> None:
    """Scaffold a new fingerprint entry, run checks, print YAML.

    Contributor onramp. Runs three guards before emitting:
    1. Slug uniqueness against the built-in catalog.
    2. Schema validation (same one the loader uses at runtime).
    3. Specificity gate — rejects regexes matching >1% of the
       synthetic adversarial corpus.

    If all three pass, prints the entry as YAML you can paste into the
    appropriate ``data/fingerprints/<category>.yaml``. Use ``--output``
    to write it to a file for review.
    """
    from recon_tool.fingerprints import _validate_fingerprint, load_fingerprints  # pyright: ignore[reportPrivateUsage]
    from recon_tool.formatter import render_error
    from recon_tool.specificity import evaluate_pattern

    console = get_console()

    # 1. Slug uniqueness
    existing = load_fingerprints()
    if any(fp.slug == slug for fp in existing):
        render_error(
            f"Slug {slug!r} already exists in the built-in catalog. "
            f"Use `recon fingerprints show {slug}` to inspect the existing entry."
        )
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # 2. Schema — build the entry dict and run the runtime validator
    entry: dict[str, object] = {
        "name": name,
        "slug": slug,
        "category": category,
        "confidence": confidence,
        "detections": [
            {
                "type": detection_type,
                "pattern": pattern,
                **({"description": description} if description else {}),
                **({"reference": reference} if reference else {}),
            }
        ],
    }
    validated = _validate_fingerprint(entry, "<wizard>")  # pyright: ignore[reportPrivateUsage]
    if validated is None:
        render_error("Schema validation failed — see warnings above.")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # 3. Specificity — only run against schema-validated detection rules.
    for det in validated.detections:
        verdict = evaluate_pattern(det.pattern, det.type)
        if verdict.threshold_exceeded:
            render_error(
                f"Pattern too broad — matched {verdict.matches}/{verdict.corpus_size} "
                f"({verdict.match_rate:.1%}) of the synthetic adversarial corpus. "
                f"Tighten the regex (anchor to ^, add vendor-specific tokens, use word "
                "boundaries) before submitting."
            )
            raise typer.Exit(code=EXIT_VALIDATION) from None

    # Emit YAML
    import yaml as _yaml

    snippet = _yaml.safe_dump(
        {"fingerprints": [entry]},
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=120,
    )

    if output:
        from pathlib import Path as _Path

        _Path(output).write_text(snippet, encoding="utf-8")
        console.print(f"  Wrote {output}")
        console.print(
            "  [dim]Next:[/dim]  merge into the matching data/fingerprints/<category>.yaml, "
            "then run [bold]recon fingerprints check[/bold]"
        )
    else:
        console.print()
        console.print("  [green]OK[/green]  Slug, schema, and specificity all pass.")
        console.print()
        console.print("  [dim]Paste into data/fingerprints/<category>.yaml:[/dim]")
        console.print()
        for line in snippet.rstrip().splitlines():
            console.print(f"    {line}")
        console.print()


@fingerprints_app.command("test")
def fingerprints_test(
    slug: str = typer.Argument(..., help="Slug to test against the public validation corpus"),
    corpus: str | None = typer.Option(
        None,
        "--corpus",
        help=(
            "Path to a newline-delimited file of apex domains. If omitted, "
            "recon looks for ~/.recon/corpus.txt; otherwise falls back to the "
            "fictional-company example at tests/fixtures/corpus-example.txt "
            "(format demo only — no real matches)."
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Run one fingerprint against a domain corpus and report which match.

    Contributor utility: after editing a fingerprint (or before PRing a
    new one), run ``recon fingerprints test <slug>`` to see which
    domains in the corpus it matches. Helps answer "is my regex too
    loose (matches noise) or too tight (misses known customers)"
    without hand-resolving DNS.

    The project ships a fictional example corpus only. To get real
    matches, either point at your own list with ``--corpus path/to/file``
    or drop a newline-delimited apex list at ``~/.recon/corpus.txt``.
    See CONTRIBUTING.md for why real-company corpora stay local.
    """
    import asyncio
    from pathlib import Path as _Path

    from recon_tool.fingerprints import load_fingerprints
    from recon_tool.resolver import resolve_tenant

    fps = load_fingerprints()
    if not any(fp.slug == slug for fp in fps):
        from recon_tool.formatter import render_error

        render_error(f"No fingerprint with slug {slug!r} in the built-in catalog.")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    using_example_corpus = False
    if corpus is None:
        from recon_tool.paths import config_dir as _config_dir

        user_corpus = _config_dir() / "corpus.txt"
        example = _find_example_corpus_path()
        if user_corpus.exists():
            corpus_path = user_corpus
        elif example is not None:
            corpus_path = example
            using_example_corpus = True
        else:
            from recon_tool.formatter import render_error

            render_error(
                "No corpus specified. Pass --corpus path/to/file or drop a "
                "newline-delimited apex list at ~/.recon/corpus.txt."
            )
            raise typer.Exit(code=EXIT_VALIDATION) from None
    else:
        corpus_path = _Path(corpus)
        if not corpus_path.exists():
            from recon_tool.formatter import render_error

            render_error(f"Corpus file not found: {corpus_path}")
            raise typer.Exit(code=EXIT_VALIDATION) from None

    domains = [
        line.strip()
        for line in corpus_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

    async def _resolve_all() -> list[tuple[str, bool, str]]:
        out: list[tuple[str, bool, str]] = []
        for domain in domains:
            try:
                info, _ = await resolve_tenant(domain, timeout=60.0)
                matched = slug in info.slugs
                detail = ""
                if matched:
                    detail = ", ".join(f"{e.source_type}:{e.raw_value[:40]}" for e in info.evidence if e.slug == slug)[
                        :120
                    ]
                out.append((domain, matched, detail))
            except Exception as exc:
                out.append((domain, False, f"error: {_fmt_exc(exc)}"))
        return out

    if json_output:
        results = asyncio.run(_resolve_all())
        payload = [{"domain": d, "matched": m, "detail": detail} for d, m, detail in results]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    console.print()
    console.print(f"  [bold]Testing {slug!r} against {len(domains)} domain{'s' if len(domains) != 1 else ''}[/bold]")
    if using_example_corpus:
        console.print("  [yellow]Using the fictional-company example corpus (no real matches expected).[/yellow]")
        console.print(
            "  [dim]Supply --corpus path/to/file or drop ~/.recon/corpus.txt to test against real apexes.[/dim]"
        )
    console.print()
    with get_err_console().status(f"Resolving {len(domains)} domains..."):
        results = asyncio.run(_resolve_all())

    hits = [(d, detail) for d, m, detail in results if m]
    misses = [d for d, m, _ in results if not m]
    for d, detail in hits:
        # detail carries evidence raw_value (e.g. BIMI VMC org); escape
        # markup and strip control bytes so it cannot inject Rich markup
        # or ANSI into the operator's terminal.
        console.print(f"    [green]MATCH[/green]  {escape(d)}    {escape(strip_control_chars(detail))}")
    console.print()
    console.print(f"  [bold]{len(hits)} of {len(domains)} matched[/bold]  ({len(misses)} did not)")
    if hits:
        console.print(f"  [dim]Next:[/dim]  recon fingerprints show {slug}")
    console.print()


@fingerprints_app.command("check")
def fingerprints_check(
    path: str | None = typer.Argument(
        None,
        help="Path to a fingerprints YAML file or directory (default: the built-in data).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print failures and the summary"),
) -> None:
    """Validate fingerprint YAML files and flag duplicate slugs.

    Contributor utility: run this before opening a PR to confirm your new
    fingerprint validates against the same schema recon uses at runtime
    (regex safety, required fields, allowed detection types, weight
    range, match_mode) and doesn't collide with an existing slug.

    Without an argument, validates the built-in catalog at
    ``recon_tool/data/fingerprints.yaml`` (or ``recon_tool/data/fingerprints/``
    once the split lands). Pass a path to validate a candidate file
    before committing it.
    """
    from pathlib import Path as _Path

    if path is None:
        # Prefer the directory layout if it exists; fall back to
        # the monolith while both coexist.
        base = _Path(__file__).resolve().parents[1] / "data"
        split_dir = base / "fingerprints"
        target = split_dir if split_dir.is_dir() else base / "fingerprints.yaml"
    else:
        target = _Path(path)

    if not target.exists():
        from recon_tool.formatter import render_error

        render_error(f"Path not found: {target}")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    from recon_tool.fingerprint_validator import validate_path

    raise typer.Exit(code=validate_path(target, quiet=quiet))


