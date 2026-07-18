"""The `recon fingerprints` Typer sub-app (list / search / show / check / new /
test the fingerprint catalog). Split out of cli.py; registered on the main app
via `app.add_typer` there. Heavy dependencies are imported inline in the
commands; the shared exception formatter comes from ``recon_tool.cli.shared``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Literal

import typer
from rich.markup import escape

from recon_tool.catalog_discovery import category_matches
from recon_tool.cli.catalog_rendering import print_field, print_indented
from recon_tool.cli.shared import fmt_exc as _fmt_exc
from recon_tool.exit_codes import EXIT_VALIDATION
from recon_tool.formatter import get_console, get_err_console, render_error
from recon_tool.validator import strip_control_chars, validate_domain

fingerprints_app = typer.Typer(help="Inspect the built-in fingerprint catalog.")
HUMAN_SEARCH_PREVIEW_LIMIT = 10
_MAX_CORPUS_FILE_BYTES = 1024 * 1024
_MAX_CORPUS_LINE_BYTES = 1024
_MAX_CORPUS_DOMAINS = 500
_MAX_CORPUS_ERROR_LENGTH = 500


@dataclass(frozen=True)
class _CorpusTestResult:
    domain: str
    status: Literal["matched", "not_matched", "error"]
    matched: bool
    detail: str = ""

_PUBLIC_DETECTION_CONTRACTS: dict[str, str] = {
    "txt": "a public TXT domain-control or account-registration indicator",
    "subdomain_txt": "a public TXT indicator at a named subdomain",
    "spf": "an SPF sender-authorization reference",
    "mx": "an MX mail-routing reference",
    "cname": "a CNAME endpoint binding",
    "cname_target": "a CNAME-chain endpoint binding",
    "srv": "an SRV service-discovery reference",
    "caa": "a CAA certificate-issuer authorization",
    "ns": "an authoritative DNS delegation",
    "dmarc_rua": "a DMARC aggregate-report destination",
}


def _public_detection_description(detection_type: str) -> str:
    """Return the bounded public meaning of a fingerprint-rule match."""
    meaning = _PUBLIC_DETECTION_CONTRACTS.get(detection_type, f"a public {detection_type} record indicator")
    return f"If matched, this rule records {meaning}; active product use is not established beyond that role."


def _fingerprint_summary(fp: Any) -> dict[str, Any]:
    """Return the stable list and search projection for one catalog record."""
    return {
        "slug": fp.slug,
        "name": fp.name,
        "category": fp.category,
        "confidence": fp.confidence,
        "detection_types": sorted({d.type for d in fp.detections}),
        "detection_count": len(fp.detections),
    }


def _legacy_detection_payload(detection: Any) -> dict[str, Any]:
    """Return the backward-compatible top-level detection projection."""
    return {
        "type": detection.type,
        "pattern": detection.pattern,
        "description": _public_detection_description(detection.type),
        "reference": detection.reference,
        "weight": detection.weight,
    }


def _legacy_fingerprint_payload(fp: Any) -> dict[str, Any]:
    """Return the original top-level show projection without new fields."""
    return {
        "slug": fp.slug,
        "name": fp.name,
        "category": fp.category,
        "confidence": fp.confidence,
        "m365": fp.m365,
        "provider_group": fp.provider_group,
        "display_group": fp.display_group,
        "match_mode": fp.match_mode,
        "detections": [_legacy_detection_payload(detection) for detection in fp.detections],
    }


def _fingerprint_record_payload(fp: Any) -> dict[str, Any]:
    """Return one complete catalog record without collapsing semantic fields."""
    return {
        "slug": fp.slug,
        "name": fp.name,
        "category": fp.category,
        "confidence": fp.confidence,
        "m365": fp.m365,
        "provider_group": fp.provider_group,
        "display_group": fp.display_group,
        "match_mode": fp.match_mode,
        "product_family": fp.product_family,
        "parent_vendor": fp.parent_vendor,
        "bimi_org": fp.bimi_org,
        "detections": [
            {
                "type": detection.type,
                "pattern": detection.pattern,
                "description": detection.description,
                "public_meaning": _public_detection_description(detection.type),
                "reference": detection.reference,
                "weight": detection.weight,
                "tier": detection.tier,
                "verified": detection.verified,
            }
            for detection in fp.detections
        ],
    }


def _render_catalog_rows(console: Any, records: list[Any] | tuple[Any, ...]) -> None:
    """Render catalog records with labels that remain associated when wrapped."""
    current_category: str | None = None
    for fp in records:
        if fp.category != current_category:
            if current_category is not None:
                console.print()
            current_category = fp.category
            print_indented(console, fp.category, indent=2, style="bold")
        types = ", ".join(sorted({d.type for d in fp.detections}))
        print_field(console, "Slug", fp.slug, indent=4)
        print_field(console, "Name", fp.name, indent=6)
        print_field(console, "Detection types", types, indent=6)
        print_field(console, "Confidence", fp.confidence, indent=6)


def _render_fingerprint_metadata(console: Any, fp: Any, *, indent: int) -> None:
    """Render metadata for one catalog record."""
    print_field(console, "Category", fp.category, indent=indent)
    print_field(console, "Confidence", fp.confidence, indent=indent)
    if fp.m365:
        print_field(console, "M365 tenant", "yes", indent=indent)
    if fp.provider_group:
        print_field(console, "Provider group", fp.provider_group, indent=indent)
    if fp.display_group:
        print_field(console, "Display group", fp.display_group, indent=indent)
    if fp.product_family:
        print_field(console, "Product family", fp.product_family, indent=indent)
    if fp.parent_vendor:
        print_field(console, "Parent vendor", fp.parent_vendor, indent=indent)
    if fp.bimi_org:
        print_field(console, "BIMI certificate org", fp.bimi_org, indent=indent)
    if fp.match_mode != "any":
        print_field(console, "Match mode", f"{fp.match_mode} (all rules must match)", indent=indent)


def _render_detection_rules(console: Any, fp: Any, *, indent: int) -> None:
    """Render every public rule for one catalog record."""
    print_indented(console, f"Detection rules ({len(fp.detections)})", indent=indent, style="bold")
    for index, detection in enumerate(fp.detections, 1):
        print_indented(console, f"{index}. [{detection.type}] {detection.pattern}", indent=indent + 2)
        if detection.description:
            print_field(console, "Catalog description", detection.description, indent=indent + 5)
        print_indented(console, _public_detection_description(detection.type), indent=indent + 5)
        if detection.type == "cname_target":
            print_field(console, "Tier", detection.tier, indent=indent + 5)
        if detection.weight != 1.0:
            print_field(console, "Weight", str(detection.weight), indent=indent + 5)
        if detection.verified:
            print_field(console, "Verified", detection.verified, indent=indent + 5)
        if detection.reference:
            print_field(console, "Reference", detection.reference, indent=indent + 5)


def _fingerprint_search_rank(fp: Any, needle: str) -> int | None:
    """Return the search rank for one record, or None when it does not match."""
    if fp.slug.lower().startswith(needle):
        return 0
    if needle in fp.slug.lower():
        return 1
    if needle in fp.name.lower():
        return 2
    if needle in fp.category.lower():
        return 3
    if any(needle in d.pattern.lower() or needle in d.description.lower() for d in fp.detections):
        return 4
    return None


def _render_fingerprint_search(console: Any, matches: list[Any], query: str) -> None:
    """Render a bounded human preview while preserving full JSON discovery."""
    grouped: dict[str, list[Any]] = {}
    for fp in matches:
        grouped.setdefault(fp.slug, []).append(fp)
    preview = list(grouped.items())[:HUMAN_SEARCH_PREVIEW_LIMIT]

    console.print()
    print_indented(
        console,
        f"{len(matches)} catalog records across {len(grouped)} unique slugs for {query!r}",
        indent=2,
        style="bold",
    )
    console.print()
    for index, (slug, records) in enumerate(preview):
        first = records[0]
        categories = ", ".join(dict.fromkeys(record.category for record in records))
        types = ", ".join(sorted({d.type for record in records for d in record.detections}))
        print_field(console, "Slug", slug, indent=4)
        print_field(console, "Name", first.name, indent=6)
        print_field(console, "Categories", categories, indent=6)
        print_field(console, "Detection types", types, indent=6)
        if len(records) > 1:
            print_field(console, "Catalog records", str(len(records)), indent=6)
        if index < len(preview) - 1:
            console.print()
    if len(grouped) > HUMAN_SEARCH_PREVIEW_LIMIT:
        console.print()
        print_indented(
            console,
            f"Showing {HUMAN_SEARCH_PREVIEW_LIMIT} of {len(grouped)} unique slugs.",
            indent=2,
        )
        print_indented(console, f"Use --json for all {len(matches)} catalog records.", indent=2)
    print_indented(console, "Next: recon fingerprints show <slug>", indent=2)
    console.print()


def _find_example_corpus_path() -> Path | None:
    for root in (Path.cwd(), *Path(__file__).resolve().parents):
        candidate = root / "tests" / "fixtures" / "corpus-example.txt"
        if candidate.exists():
            return candidate
    return None


def _read_fingerprint_corpus(path: Path) -> list[str]:
    """Read one bounded UTF-8 corpus without exposing rejected row contents."""
    with path.open("rb") as handle:
        raw = handle.read(_MAX_CORPUS_FILE_BYTES + 1)
    if len(raw) > _MAX_CORPUS_FILE_BYTES:
        raise ValueError(f"Corpus exceeds the {_MAX_CORPUS_FILE_BYTES:,}-byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Corpus must be valid UTF-8") from exc

    domains: list[str] = []
    seen: set[str] = set()
    domain_rows = 0
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        if len(raw_line.encode("utf-8")) > _MAX_CORPUS_LINE_BYTES:
            raise ValueError(f"Corpus line {line_number} exceeds the {_MAX_CORPUS_LINE_BYTES:,}-byte limit")
        domain = raw_line.strip()
        if not domain or domain.startswith("#"):
            continue
        domain_rows += 1
        if domain_rows > _MAX_CORPUS_DOMAINS:
            raise ValueError(f"Corpus exceeds the {_MAX_CORPUS_DOMAINS:,}-domain limit")
        try:
            normalized = validate_domain(domain)
        except ValueError as exc:
            raise ValueError(f"Corpus line {line_number} has invalid domain format") from exc
        if normalized not in seen:
            seen.add(normalized)
            domains.append(normalized)
    if not domains:
        raise ValueError("Corpus contains no domains")
    return domains


def _bounded_corpus_error(exc: BaseException) -> str:
    """Return control-free bounded lookup detail for text and JSON output."""
    cleaned = strip_control_chars(_fmt_exc(exc), max_len=_MAX_CORPUS_ERROR_LENGTH + 1)
    if len(cleaned) > _MAX_CORPUS_ERROR_LENGTH:
        cleaned = f"{cleaned[:_MAX_CORPUS_ERROR_LENGTH]} [truncated]"
    return f"error: {cleaned}"


def _load_fingerprint_corpus(corpus: str | None) -> tuple[list[str], bool]:
    """Resolve the configured corpus path and validate all input before lookup."""
    using_example_corpus = False
    if corpus is None:
        from recon_tool.paths import config_dir

        user_corpus = config_dir() / "corpus.txt"
        example = _find_example_corpus_path()
        if user_corpus.exists():
            corpus_path = user_corpus
        elif example is not None:
            corpus_path = example
            using_example_corpus = True
        else:
            render_error(
                "No corpus specified. Pass --corpus path/to/file or drop a "
                "newline-delimited apex list at ~/.recon/corpus.txt."
            )
            raise typer.Exit(code=EXIT_VALIDATION) from None
    else:
        corpus_path = Path(corpus)
        if not corpus_path.exists():
            render_error(f"Corpus file not found: {corpus_path}")
            raise typer.Exit(code=EXIT_VALIDATION) from None

    try:
        return _read_fingerprint_corpus(corpus_path), using_example_corpus
    except (OSError, ValueError) as exc:
        render_error(f"Could not use corpus: {_fmt_exc(exc)}")
        raise typer.Exit(code=EXIT_VALIDATION) from None


@fingerprints_app.command("list", short_help="Summarize fingerprints.")
def fingerprints_list(
    category: str | None = typer.Option(
        None, "--category", "-c", help="Filter by category word prefix or phrase"
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

    With no filters, shows a per-category summary because the full catalog is
    too large for a useful prompt. Use --category to scope the result, --all
    for every record, or the search command for free-text discovery.
    """
    from recon_tool.fingerprints import load_fingerprints

    fps = load_fingerprints()
    had_filter = category is not None or detection_type is not None
    if category is not None:
        category = category.strip()
        if not category:
            render_error("Fingerprint category filter cannot be empty.")
            raise typer.Exit(code=EXIT_VALIDATION) from None
        fps = tuple(fp for fp in fps if category_matches(fp.category, category))
    if detection_type is not None:
        dtype = detection_type.strip().lower()
        if not dtype:
            render_error("Fingerprint detection type filter cannot be empty.")
            raise typer.Exit(code=EXIT_VALIDATION) from None
        fps = tuple(fp for fp in fps if any(d.type.lower() == dtype for d in fp.detections))

    if json_output:
        payload = [_fingerprint_summary(fp) for fp in fps]
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
        console.print(f"  [bold]{len(fps)} catalog records across {len(by_cat)} categories[/bold]")
        console.print()
        width = max(len(cat) for cat in by_cat)
        for cat, n in sorted(by_cat.items(), key=lambda x: (-x[1], x[0])):
            console.print(f"    {cat:<{width}s}  {n:>4d}")
        console.print()
        console.print("  [dim]Next:[/dim]")
        console.print("    recon fingerprints list --category <name>")
        console.print("    recon fingerprints search <query>")
        console.print("    recon fingerprints show <slug>")
        console.print()
        return

    console.print()
    console.print(f"  [bold]{len(fps)} catalog record{'s' if len(fps) != 1 else ''}[/bold]")
    console.print()
    _render_catalog_rows(console, sorted(fps, key=lambda fp: (fp.category, fp.slug)))
    console.print()


@fingerprints_app.command("search", short_help="Search fingerprints.")
def fingerprints_search(
    query: str = typer.Argument(..., help="Search term matched against slug, name, category, and detection patterns"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Search fingerprints by slug, name, category, or detection pattern."""
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
        rank = _fingerprint_search_rank(fp, needle)
        if rank is not None:
            ranked.append((rank, fp))

    ranked.sort(key=lambda x: (x[0], x[1].slug))
    matches = [fp for _, fp in ranked]

    if json_output:
        payload = [_fingerprint_summary(fp) for fp in matches]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    if not matches:
        console.print(f"  No fingerprints match {escape(repr(query))}.")
        console.print("  [dim]Try a shorter or differently-spelled query, or browse by category:[/dim]")
        console.print("  [dim]  recon fingerprints list[/dim]")
        return

    _render_fingerprint_search(console, matches, query)


@fingerprints_app.command("show", short_help="Show one fingerprint.")
def fingerprints_show(
    slug: str = typer.Argument(..., help="Slug to inspect, such as cloudflare or exchange-onprem"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Show the full definition of a single fingerprint.

    Synthetic slugs emitted by a source probe are documented here too, so a
    slug observed in output always has a discoverable provenance note.
    """
    # Synthetic slugs aren't in fingerprints.yaml — they're emitted
    # by source-layer probes. Document provenance so users aren't left
    # grepping the code.
    _SYNTHETIC_SLUGS: dict[str, tuple[str, str]] = {
        "exchange-onprem": (
            "Exchange-style endpoint indicator",
            "Emitted by recon_tool.sources.dns._detect_exchange_endpoints when "
            "owa./outlook./exchange./mail-ex./autodiscover. subdomains resolve "
            "(wildcard-guarded). This is a public naming observation; it does "
            "not establish server software or deployment model.",
        ),
        "self-hosted-mail": (
            "Custom or unclassified MX",
            "Emitted by recon_tool.sources.dns_email.detect_mx when MX records "
            "exist and no known cloud-provider or gateway fingerprint matched. "
            "The raw_value field carries the MX hosts, but recon does not infer "
            "who operates them or whether they are self-hosted.",
        ),
        "null-mx": (
            "Null MX (domain does not accept email)",
            "Emitted by recon_tool.sources.dns_email.detect_mx for the RFC 7505 "
            "Null MX form `0 .`. This is an explicit public declaration that "
            "the domain does not accept email.",
        ),
    }

    from recon_tool.fingerprints import load_fingerprints

    fps = load_fingerprints()
    matches = tuple(fp for fp in fps if fp.slug == slug)
    match = matches[0] if matches else None
    if match is None and slug in _SYNTHETIC_SLUGS:
        name, note = _SYNTHETIC_SLUGS[slug]
        if json_output:
            typer.echo(json.dumps({"slug": slug, "name": name, "synthetic": True, "note": note}, indent=2))
            return
        console = get_console()
        console.print()
        console.print(f"  [bold]{name}[/bold]  ({slug})")
        console.print("    [dim]synthetic slug emitted by a source probe, not loaded from fingerprints.yaml[/dim]")
        console.print()
        console.print(f"  {note}")
        console.print()
        return
    if match is None:
        from recon_tool.formatter import render_error

        candidates = list(dict.fromkeys(fp.slug for fp in fps if slug.lower() in fp.slug.lower()))[:5]
        render_error(f"No fingerprint with slug {slug!r}.")
        if candidates:
            get_console().print(f"  Did you mean: {', '.join(candidates)}?")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    if json_output:
        payload = _legacy_fingerprint_payload(match)
        payload["record_count"] = len(matches)
        payload["records"] = [_fingerprint_record_payload(record) for record in matches]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    console.print()
    print_indented(console, f"{match.name} ({match.slug})", indent=2, style="bold")
    if len(matches) == 1:
        _render_fingerprint_metadata(console, match, indent=4)
        console.print()
        _render_detection_rules(console, match, indent=2)
        console.print()
        return

    console.print()
    console.print(f"  [bold]Catalog records ({len(matches)})[/bold]")
    for index, record in enumerate(matches, 1):
        console.print()
        console.print(f"    [bold]Record {index}[/bold]")
        _render_fingerprint_metadata(console, record, indent=6)
        console.print()
        _render_detection_rules(console, record, indent=6)
    console.print()


@fingerprints_app.command("new", short_help="Scaffold a fingerprint.")
def fingerprints_new(
    slug: str = typer.Argument(..., help="Unique slug for the new fingerprint (lowercase, hyphen-separated)"),
    name: str = typer.Option(..., "--name", "-n", help="Human-readable service name (e.g. 'Synthetic Delta Security')"),
    category: str = typer.Option(
        "Misc",
        "--category",
        "-c",
        help="Existing category name; use fingerprints list to see options",
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
    """Scaffold a fingerprint and enforce slug, schema, and specificity checks."""
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
                "verified": date.today().isoformat(),
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


@fingerprints_app.command("test", short_help="Test against a corpus.")
def fingerprints_test(
    slug: str = typer.Argument(..., help="Slug to test against a local validation corpus"),
    corpus: str | None = typer.Option(
        None,
        "--corpus",
        help=(
            "Path to a newline-delimited file of apex domains. If omitted, "
            "recon looks for ~/.recon/corpus.txt; otherwise falls back to the "
            "reserved synthetic example at tests/fixtures/corpus-example.txt "
            "(format demo only; no real matches)."
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Resolve a local corpus through live lookups and report fingerprint matches.

    Each corpus row uses ordinary collection. DNS infrastructure may observe
    queries, public CT and identity sources can receive requests, and MTA-STS
    remains the one default target-owned HTTP request.
    """
    import asyncio

    from recon_tool.fingerprints import load_fingerprints
    from recon_tool.resolver import resolve_tenant

    fps = load_fingerprints()
    if not any(fp.slug == slug for fp in fps):
        render_error(f"No fingerprint with slug {slug!r} in the built-in catalog.")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    domains, using_example_corpus = _load_fingerprint_corpus(corpus)

    async def _resolve_all() -> list[_CorpusTestResult]:
        out: list[_CorpusTestResult] = []
        for domain in domains:
            try:
                info, _ = await resolve_tenant(domain, timeout=60.0)
                matched = slug in info.slugs
                detail = ""
                if matched:
                    detail = ", ".join(f"{e.source_type}:{e.raw_value[:40]}" for e in info.evidence if e.slug == slug)[
                        :120
                    ]
                status: Literal["matched", "not_matched"] = "matched" if matched else "not_matched"
                out.append(_CorpusTestResult(domain=domain, status=status, matched=matched, detail=detail))
            except Exception as exc:
                out.append(
                    _CorpusTestResult(
                        domain=domain,
                        status="error",
                        matched=False,
                        detail=_bounded_corpus_error(exc),
                    )
                )
        return out

    if json_output:
        results = asyncio.run(_resolve_all())
        payload = [
            {
                "domain": result.domain,
                "status": result.status,
                "matched": result.matched,
                "detail": result.detail,
            }
            for result in results
        ]
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

    hits = [result for result in results if result.status == "matched"]
    misses = [result for result in results if result.status == "not_matched"]
    errors = [result for result in results if result.status == "error"]
    for result in hits:
        # detail carries evidence raw_value (e.g. BIMI VMC org); escape
        # markup and strip control bytes so it cannot inject Rich markup
        # or ANSI into the operator's terminal.
        console.print(
            f"    [green]MATCH[/green]  {escape(strip_control_chars(result.domain))}    "
            f"{escape(strip_control_chars(result.detail))}"
        )
    for result in errors:
        console.print(
            f"    [red]ERROR[/red]  {escape(strip_control_chars(result.domain))}    {escape(result.detail)}"
        )
    console.print()
    error_label = "lookup error" if len(errors) == 1 else "lookup errors"
    console.print(
        f"  [bold]{len(hits)} of {len(domains)} matched[/bold]  "
        f"({len(misses)} did not match; {len(errors)} {error_label})"
    )
    if hits:
        console.print(f"  [dim]Next:[/dim]  recon fingerprints show {slug}")
    console.print()


@fingerprints_app.command("check", short_help="Validate fingerprint files.")
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

    Without an argument, validates canonical YAML in a source checkout or the
    packaged generated catalog in an installed wheel. Pass a path to validate a
    candidate YAML file before committing it.
    """
    from pathlib import Path as _Path

    if path is None:
        from recon_tool.fingerprint_validator import validate_builtin_artifact, validate_path

        split_dir = _Path(__file__).resolve().parents[1] / "data" / "fingerprints"
        if split_dir.is_dir():
            raise typer.Exit(code=validate_path(split_dir, quiet=quiet))
        raise typer.Exit(code=validate_builtin_artifact(quiet=quiet))

    target = _Path(path)
    if not target.exists():
        from recon_tool.formatter import render_error

        render_error(f"Path not found: {target}")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    from recon_tool.fingerprint_validator import validate_path

    raise typer.Exit(code=validate_path(target, quiet=quiet))
