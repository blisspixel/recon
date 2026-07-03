"""Batch command implementation: input bounds, per-domain processing, emitters.

Extracted from cli.py (docs/roadmap.md god-file track). Plain command-logic
helpers; the Typer app and the thin @app.command wrappers stay in cli.py, which
imports this module and references the orchestrators through a small assignment
facade. Imports the shared cli helpers / formatter; never imports cli.py.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, TextIO

import typer
from rich.markup import escape

from recon_tool.cli_shared import fmt_exc as _fmt_exc
from recon_tool.exit_codes import (
    EXIT_INTERNAL,
    EXIT_NO_DATA,
    EXIT_VALIDATION,
)
from recon_tool.formatter import get_console, get_err_console
from recon_tool.validator import strip_control_chars


class _BatchInputError(ValueError):
    """Batch input exceeded a safety bound (size or domain count)."""


# Batch-input safety bounds. Cap the per-line read (so a newline-free
# multi-GB "line" cannot be buffered whole), the cumulative bytes (so a stream
# of millions of blank/comment lines, which never increments the domain count,
# cannot loop unbounded), and the domain count itself (to prevent OOM).
_MAX_BATCH_DOMAINS = 10000


_MAX_BATCH_LINE_BYTES = 1024


_MAX_BATCH_FILE_BYTES = 10 * 1024 * 1024


def read_batch_domains(stream: TextIO) -> list[str]:
    """Stream domain lines from a text stream under the batch safety bounds.

    Reads line by line so a huge input is never buffered whole, skips blank
    and ``#``-comment lines, and raises :class:`_BatchInputError` if the input
    exceeds the cumulative-size or domain-count cap. Shared by the file path
    and the stdin path (``recon batch -``).
    """
    domains: list[str] = []
    total_bytes = 0
    while True:
        line = stream.readline(_MAX_BATCH_LINE_BYTES + 1)
        if not line:
            break
        if len(line) > _MAX_BATCH_LINE_BYTES:
            msg = f"Batch input line exceeds maximum length of {_MAX_BATCH_LINE_BYTES} bytes"
            raise _BatchInputError(msg)
        total_bytes += len(line)
        if total_bytes > _MAX_BATCH_FILE_BYTES:
            msg = f"Batch input exceeds maximum size of {_MAX_BATCH_FILE_BYTES // (1024 * 1024)} MB"
            raise _BatchInputError(msg)
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            domains.append(stripped)
            if len(domains) > _MAX_BATCH_DOMAINS:
                msg = f"Batch input exceeds maximum of {_MAX_BATCH_DOMAINS} domains"
                raise _BatchInputError(msg)
    return domains


async def discover(
    domain: str,
    *,
    output_path: str | None,
    skip_ct: bool,
    timeout: float,
    drop_intra_org: bool,
    min_count: int,
) -> None:
    """Single-domain fingerprint-discovery pipeline.

    Resolves the domain, walks the unclassified CNAME chains the surface
    classifier captured, applies the intra-org and already-covered filters,
    and emits the candidate list in the same shape as the corpus-scale
    ``triage_candidates.py``. Output is consumable by the
    ``/recon-fingerprint-triage`` skill.
    """
    import json as json_mod

    from recon_tool.discovery import find_candidates
    from recon_tool.formatter import render_error
    from recon_tool.models import ReconLookupError
    from recon_tool.resolver import resolve_tenant
    from recon_tool.validator import validate_domain

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        render_error(str(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from None

    try:
        info, _results = await resolve_tenant(validated, timeout=timeout, skip_ct=skip_ct)
    except ReconLookupError as exc:
        render_error(str(exc))
        raise typer.Exit(code=EXIT_NO_DATA) from None
    except Exception as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from None

    # Convert TenantInfo's unclassified_cname_chains into the (apex, [{subdomain, chain}])
    # shape ``find_candidates`` consumes. Same data, different transport.
    unclassified_records = [
        {"subdomain": uc.subdomain, "chain": list(uc.chain)} for uc in info.unclassified_cname_chains
    ]
    fingerprints_dir = Path(__file__).resolve().parent / "data" / "fingerprints"
    candidates = find_candidates(
        [(info.queried_domain, unclassified_records)],
        fingerprints_dir=fingerprints_dir,
        min_count=min_count,
        drop_intra_org=drop_intra_org,
    )

    payload = json_mod.dumps(candidates, indent=2)
    if output_path is None:
        typer.echo(payload)
    else:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        typer.echo(f"wrote {out} ({len(candidates)} candidates)", err=True)


def batch_validate_flags(
    *,
    json_output: bool,
    markdown: bool,
    csv_output: bool,
    ndjson: bool,
    include_ecosystem: bool,
    summary: bool = False,
) -> None:
    """Reject mutually-exclusive output flags and the --include-ecosystem constraint."""
    from recon_tool.formatter import render_error

    if sum([json_output, markdown, csv_output, ndjson]) > 1:
        render_error("--json, --md, --csv, and --ndjson are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION)
    # --summary is a batch-scope aggregate. It pairs with --json (machine
    # output) or stands alone (panel); the per-domain formats have no cohort view.
    if summary and (markdown or csv_output or ndjson):
        render_error("--summary cannot combine with --md, --csv, or --ndjson")
        raise typer.Exit(code=EXIT_VALIDATION)
    # --summary and --include-ecosystem are different batch-scope aggregates; the
    # summary path returns before the ecosystem envelope is emitted, so combining
    # them would silently drop the hypergraph. Reject rather than mislead.
    if summary and include_ecosystem:
        render_error("--summary cannot combine with --include-ecosystem")
        raise typer.Exit(code=EXIT_VALIDATION)
    # --include-ecosystem requires --json. The hypergraph is a batch-scope
    # envelope sibling to the per-domain entries with no natural place in the
    # panel, markdown, CSV, or NDJSON outputs (NDJSON streams per-domain and the
    # hypergraph needs the full set).
    if include_ecosystem and not json_output:
        render_error("--include-ecosystem requires --json")
        raise typer.Exit(code=EXIT_VALIDATION)


def _batch_load_domains(file: str, console: Any, *, announce_dupes: bool) -> list[str]:
    """Read the domain list (file path or "-" for stdin), dedupe in input order.

    Raises ``typer.Exit`` on a missing/unreadable/malformed file or an empty list.
    """
    import sys as sys_mod

    from recon_tool.formatter import render_error

    # A literal "-" reads the domain list from stdin (cat domains.txt | recon
    # batch -); otherwise treat the argument as a file path. Both go through the
    # same bounded line reader.
    from_stdin = file == "-"
    try:
        if from_stdin:
            domain_list = read_batch_domains(sys_mod.stdin)
        else:
            path = Path(file)
            if not path.exists():
                render_error(f"File not found: {file}")
                raise typer.Exit(code=EXIT_VALIDATION)
            with path.open(encoding="utf-8") as f:
                domain_list = read_batch_domains(f)
    except _BatchInputError as exc:
        render_error(str(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from None
    except OSError as exc:
        render_error(f"Cannot read file: {exc}")
        raise typer.Exit(code=EXIT_INTERNAL) from None

    if not domain_list:
        source = "stdin" if from_stdin else "file"
        render_error(f"No domains found in {source}")
        raise typer.Exit(code=EXIT_VALIDATION)

    # Deduplicate while preserving input order
    seen: set[str] = set()
    unique_domains: list[str] = []
    for d in domain_list:
        d_lower = d.lower().strip()
        if d_lower not in seen:
            seen.add(d_lower)
            unique_domains.append(d)
    if len(unique_domains) < len(domain_list) and announce_dupes:
        skipped = len(domain_list) - len(unique_domains)
        console.print(f"  [dim]{skipped} duplicate(s) removed[/dim]")
    return unique_domains


def _batch_apply_fusion(info: Any) -> Any:
    """Bayesian fusion for batch results: ``posterior_observations`` + ``slug_confidences``.

    Pure post-processing over the already-resolved TenantInfo, no extra network
    calls. Unlike ``_lookup_apply_fusion`` this omits ``evidence_ranked`` on each
    posterior, preserving the batch JSON shape that shipped before this refactor.
    """
    from dataclasses import replace

    from recon_tool.bayesian import infer_from_tenant_info
    from recon_tool.fusion import compute_slug_posteriors
    from recon_tool.models import NodeConflict, NodeUnitCounterfactual, PosteriorObservation

    result = infer_from_tenant_info(info)
    return replace(
        info,
        slug_confidences=compute_slug_posteriors(info.evidence),
        posterior_observations=tuple(
            PosteriorObservation(
                name=p.name,
                description=p.description,
                posterior=p.posterior,
                interval_low=p.interval_low,
                interval_high=p.interval_high,
                evidence_used=p.evidence_used,
                n_eff=p.n_eff,
                sparse=p.sparse,
                conflict_provenance=tuple(
                    NodeConflict(field=c.field, sources=c.sources, magnitude=c.magnitude) for c in p.conflict_provenance
                ),
                # evidence_ranked stays deliberately omitted here (the batch
                # JSON shape freeze predates it); the 2.2.0 diagnostics are
                # additive and carried in both lookup and batch shapes.
                entropy_reduction_nats=p.entropy_reduction_nats,
                unit_counterfactuals=tuple(
                    NodeUnitCounterfactual(
                        unit=c.unit,
                        kind=c.kind,
                        observed=c.observed,
                        posterior_without=c.posterior_without,
                        delta=c.delta,
                    )
                    for c in p.unit_counterfactuals
                ),
            )
            for p in result.posteriors
        ),
    )


def _batch_attach_shared_tokens(json_results: list[dict[str, Any]], batch_infos: dict[str, Any]) -> None:
    """Attach ``shared_verification_tokens`` peer lists in place.

    Keyed by ``queried_domain`` (the canonical normalized form) when at least two
    domains in the batch publish the same site-verification token.
    """
    from recon_tool.clustering import compute_shared_tokens

    domain_tokens = {d: info.site_verification_tokens for d, info in batch_infos.items()}
    clusters = compute_shared_tokens(domain_tokens)
    if not clusters:
        return
    for entry in json_results:
        key = entry.get("queried_domain")
        if not isinstance(key, str):
            continue
        peers = clusters.get(key)
        if peers:
            entry["shared_verification_tokens"] = [{"token": e.token, "peer": e.peer} for e in peers]


def _batch_attach_peers(json_results: list[dict[str, Any]], batch_infos: dict[str, Any]) -> None:
    """Attach ``shared_tenant`` and ``shared_display_name`` peer lists in place.

    Tenant-ID sharing is cryptographically strong (same M365 customer account);
    display-name overlap is hedged (same brand / likely related, but
    customer-supplied so not cryptographic). Both surface as a per-domain peer
    list so batch consumers can pull related apexes without re-resolving them.
    """
    from recon_tool.clustering import compute_display_name_clusters, compute_tenant_clusters

    domain_tenants = {d: info.tenant_id for d, info in batch_infos.items()}
    domain_names = {d: info.display_name for d, info in batch_infos.items()}
    tenant_clusters = compute_tenant_clusters(domain_tenants)
    display_clusters = compute_display_name_clusters(domain_names)

    # Build per-domain peer indexes for quick lookup.
    tenant_peers: dict[str, list[dict[str, object]]] = {}
    for tc in tenant_clusters:
        for d in tc.domains:
            tenant_peers.setdefault(d, []).append(
                {
                    "tenant_id": tc.tenant_id,
                    "peers": [p for p in tc.domains if p != d],
                }
            )
    display_peers: dict[str, list[dict[str, object]]] = {}
    for dc in display_clusters:
        for d, raw in zip(dc.domains, dc.raw_names, strict=True):
            display_peers.setdefault(d, []).append(
                {
                    "display_name": raw,
                    "normalized_name": dc.normalized_name,
                    "peers": [p for p in dc.domains if p != d],
                }
            )

    if not (tenant_peers or display_peers):
        return
    for entry in json_results:
        key = entry.get("queried_domain")
        if not isinstance(key, str):
            continue
        if key in tenant_peers:
            entry["shared_tenant"] = tenant_peers[key]
        if key in display_peers:
            entry["shared_display_name"] = display_peers[key]


def batch_emit_json(results: list[object], batch_infos: dict[str, Any], *, include_ecosystem: bool) -> None:
    """Assemble the batch JSON array (with cross-domain enrichment) and emit it."""
    import json as json_mod

    json_results: list[dict[str, Any]] = [r for r in results if r is not None]  # type: ignore[misc]

    if batch_infos:
        _batch_attach_shared_tokens(json_results, batch_infos)
        _batch_attach_peers(json_results, batch_infos)

    # Ecosystem hypergraph. Off by default. When opted in via
    # --include-ecosystem, emit hyperedges over the batch's TenantInfo set as a
    # top-level envelope sibling to the per-domain entries.
    if include_ecosystem:
        # SH9: when --include-ecosystem is set, always emit the BatchResult
        # wrapper, even when no domain resolved. Previously this fell back to a
        # bare array on an all-failed batch, flipping the top-level type exactly
        # when a consumer's error path is already stressed. Errors ride under
        # domains; hyperedges are empty when there were no resolved infos.
        hyperedges: list[Any] = []
        if batch_infos:
            from recon_tool.ecosystem import build_ecosystem_hyperedges

            hyperedges = list(build_ecosystem_hyperedges(batch_infos))
        ecosystem_payload = {
            "record_type": "batch_result",  # SH7 discriminator
            "ecosystem_hyperedges": [
                {
                    "edge_type": e.edge_type,
                    "key": e.key,
                    "members": list(e.members),
                }
                for e in hyperedges
            ],
            "domains": json_results,
        }
        typer.echo(json_mod.dumps(ecosystem_payload, indent=2))
        return

    typer.echo(json_mod.dumps(json_results, indent=2))


def batch_emit_summary(batch_infos: dict[str, Any], attempted: int, console: Any, *, as_json: bool) -> None:
    """Emit one aggregate-only cohort summary over the resolved batch.

    Stateless: computed live from the resolved records, stores nothing, ships no
    baselines, names no domain. The richer caller-grouped analysis lives in the
    downstream reducer under ``validation/aggregate/``.
    """
    import json as json_mod

    from recon_tool.cohort_summary import build_summary_document, render_cohort_summary
    from recon_tool.formatter import format_tenant_dict

    records = [format_tenant_dict(info) for info in batch_infos.values()]
    document = build_summary_document(records, attempted=attempted)
    if as_json:
        typer.echo(json_mod.dumps(document, indent=2))
    else:
        console.print(render_cohort_summary(document))


async def _batch_emit_ndjson(domain_list: list[str], process_one: Any, error_prefix: str) -> None:
    """Stream one JSON object per line, flushed as each domain completes.

    Skips the post-batch enrichment (shared tokens, tenant peers, display-name
    clusters) because those need every result before any can be emitted. Trades
    batch-wide enrichment for constant memory and visible progress on large
    corpora.
    """
    import json as json_mod
    import sys as sys_mod

    tasks = [asyncio.create_task(process_one(d)) for d in domain_list]
    for fut in asyncio.as_completed(tasks):
        result = await fut
        if isinstance(result, dict):
            typer.echo(json_mod.dumps(result))
            # Flush stdout so downstream pipelines see each line as it lands.
            sys_mod.stdout.flush()
        elif isinstance(result, str) and result.startswith(error_prefix):
            typer.echo(result.removeprefix(error_prefix), err=True)


def _batch_render_results(
    results: list[object],
    batch_infos: dict[str, Any],
    console: Any,
    *,
    json_output: bool,
    csv_output: bool,
    markdown: bool,
    include_ecosystem: bool,
    error_prefix: str,
) -> None:
    """Render gathered batch results in input order for the chosen output mode."""
    from recon_tool.formatter import render_error

    if json_output:
        batch_emit_json(results, batch_infos, include_ecosystem=include_ecosystem)
    elif csv_output:
        from recon_tool.formatter import format_batch_csv

        csv_rows: list[Any] = [r for r in results if isinstance(r, tuple) and len(r) == 3]
        typer.echo(format_batch_csv(csv_rows), nl=False)
    elif markdown:
        for r in results:
            if r is None:
                continue
            # A resolve error is carried as an internal sentinel-prefixed string
            # (see error_prefix). Surface it on stderr like the default branch
            # instead of echoing the NUL sentinel into the markdown stdout.
            if isinstance(r, str) and r.startswith(error_prefix):
                render_error(r[len(error_prefix) :])
            else:
                typer.echo(r)
                typer.echo("---\n")
    else:
        for r in results:
            if r is None:
                continue
            if isinstance(r, str) and r.startswith(error_prefix):
                render_error(r[len(error_prefix) :])
            else:
                console.print(r)
                console.print()


def _batch_error_result(
    domain: str,
    message: str,
    *,
    json_output: bool,
    ndjson: bool,
    csv_output: bool,
    markdown: bool,
    markdown_skips: bool,
    error_prefix: str,
) -> object:
    """Shape a per-domain error for the active output mode.

    ``markdown_skips`` distinguishes the validate-error path (markdown yields
    nothing) from the resolve-error path (markdown falls through to the display
    sentinel), preserving the pre-refactor behaviour exactly.
    """
    if json_output or ndjson:
        # SH8: machine-readable error_kind so a consumer can route on a code
        # rather than the free-text message. markdown_skips marks the
        # validate-error path; otherwise it is a lookup error (timeout split out).
        if markdown_skips:
            error_kind = "validation"
        elif "timeout" in message.lower() or "timed out" in message.lower():
            error_kind = "timeout"
        else:
            error_kind = "lookup"
        # SH7: record_type discriminator (this is the error shape).
        return {"domain": domain, "error": message, "error_kind": error_kind, "record_type": "error"}
    if csv_output:
        return (domain, None, message)
    if markdown and markdown_skips:
        return None
    return f"{error_prefix}{domain}: {message}"


def _batch_success_result(
    info: Any,
    domain: str,
    *,
    json_output: bool,
    ndjson: bool,
    csv_output: bool,
    markdown: bool,
    include_unclassified: bool,
) -> object:
    """Shape a successful per-domain result for the active output mode."""
    from recon_tool.formatter import format_tenant_dict, format_tenant_markdown, render_tenant_panel

    if json_output or ndjson:
        return format_tenant_dict(info, include_unclassified=include_unclassified)
    if csv_output:
        return (domain, info, None)
    if markdown:
        return format_tenant_markdown(info)
    return render_tenant_panel(info)


async def _batch_process_one(
    domain: str,
    *,
    semaphore: asyncio.Semaphore,
    batch_infos: dict[str, Any],
    timeout: float,
    skip_ct: bool,
    fusion: bool,
    json_output: bool,
    ndjson: bool,
    csv_output: bool,
    markdown: bool,
    include_unclassified: bool,
    error_prefix: str,
) -> object:
    """Resolve a single domain under the semaphore and shape its result.

    Stashes the TenantInfo in ``batch_infos`` (keyed by queried_domain) so the
    post-batch token / tenant / display-name clustering can run.
    """
    from recon_tool.models import ReconLookupError
    from recon_tool.resolver import resolve_tenant
    from recon_tool.validator import validate_domain

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        return _batch_error_result(
            domain,
            str(exc),
            json_output=json_output,
            ndjson=ndjson,
            csv_output=csv_output,
            markdown=markdown,
            markdown_skips=True,
            error_prefix=error_prefix,
        )

    async with semaphore:
        try:
            # Small delay between domains to avoid burst-flooding upstream
            # endpoints (Microsoft, DNS). The semaphore caps concurrency, but
            # without a delay all N domains fire at once.
            await asyncio.sleep(0.1)
            info, _results = await resolve_tenant(validated, timeout=timeout, skip_ct=skip_ct)
            if fusion:
                info = _batch_apply_fusion(info)
            batch_infos[info.queried_domain] = info
            return _batch_success_result(
                info,
                domain,
                json_output=json_output,
                ndjson=ndjson,
                csv_output=csv_output,
                markdown=markdown,
                include_unclassified=include_unclassified,
            )
        except ReconLookupError as exc:
            return _batch_error_result(
                domain,
                str(exc),
                json_output=json_output,
                ndjson=ndjson,
                csv_output=csv_output,
                markdown=markdown,
                markdown_skips=False,
                error_prefix=error_prefix,
            )
        except Exception as exc:
            return _batch_error_result(
                domain,
                str(exc),
                json_output=json_output,
                ndjson=ndjson,
                csv_output=csv_output,
                markdown=markdown,
                markdown_skips=False,
                error_prefix=error_prefix,
            )


async def batch(
    file: str,
    json_output: bool,
    markdown: bool,
    concurrency: int,
    timeout: float,
    csv_output: bool = False,
    *,
    include_unclassified: bool = False,
    skip_ct: bool = False,
    ndjson: bool = False,
    include_ecosystem: bool = False,
    fusion: bool = False,
    summary: bool = False,
) -> None:
    """Process multiple domains from a file with controlled concurrency.

    Rate limiting: Each domain hits 3+ external endpoints concurrently.
    The semaphore caps domain-level concurrency, and the HTTP transport
    retries on 429/503 with exponential backoff. For large batch files,
    an inter-domain delay prevents burst-flooding upstream endpoints.

    Output modes:
      * default — rendered tenant panel per domain
      * ``json_output`` — single JSON array at the end (back-compat shape)
      * ``markdown`` — rendered markdown per domain
      * ``csv_output`` — flat CSV of headline fields
      * ``ndjson`` — one JSON object per line, flushed as each domain
        completes. Recommended for large corpora where ``json_output`` would
        buffer the entire result set in memory.
    """
    from recon_tool.models import TenantInfo as _TenantInfo

    console = get_console()

    batch_validate_flags(
        json_output=json_output,
        markdown=markdown,
        csv_output=csv_output,
        ndjson=ndjson,
        include_ecosystem=include_ecosystem,
        summary=summary,
    )

    domain_list = _batch_load_domains(
        file, console, announce_dupes=not json_output and not markdown and not csv_output and not ndjson
    )

    semaphore = asyncio.Semaphore(concurrency)

    # Batch-scope token clustering. Each successful resolution
    # stashes its TenantInfo here keyed by the *input* domain string,
    # so the post-processing pass can compute `shared_verification_tokens`
    # across every domain in the batch. Scoped to this batch run — never
    # persisted to disk cache, never shared between batch invocations.
    batch_infos: dict[str, _TenantInfo] = {}

    # Sentinel prefix for error messages returned from _process_one.
    # Errors are collected as strings and printed in order after all tasks complete,
    # preventing interleaved output from concurrent coroutines.
    _ERROR_PREFIX = "\x00ERR:"

    async def _run_one(domain: str) -> object:
        """Bind the batch-scoped state and delegate to ``_batch_process_one``."""
        return await _batch_process_one(
            domain,
            semaphore=semaphore,
            batch_infos=batch_infos,
            timeout=timeout,
            skip_ct=skip_ct,
            fusion=fusion,
            json_output=json_output,
            ndjson=ndjson,
            csv_output=csv_output,
            markdown=markdown,
            include_unclassified=include_unclassified,
            error_prefix=_ERROR_PREFIX,
        )

    # Gather all results concurrently, then output in input-file order.
    # This prevents interleaved output from concurrent coroutines.
    total = len(domain_list)
    completed = 0

    async def _tracked(domain: str) -> object:
        nonlocal completed
        result = await _run_one(domain)
        completed += 1
        if not summary and not json_output and not markdown and not csv_output:
            safe = escape(strip_control_chars(domain))
            get_err_console().print(f"  [{completed}/{total}] {safe}", style="dim", highlight=False)
        return result

    # NDJSON streaming path, flushed per-domain (see helper for the trade-off).
    if ndjson:
        await _batch_emit_ndjson(domain_list, _run_one, _ERROR_PREFIX)
        return

    tasks = [_tracked(d) for d in domain_list]
    results = await asyncio.gather(*tasks)

    # --summary collapses the batch into one aggregate-only cohort summary.
    if summary:
        batch_emit_summary(batch_infos, len(domain_list), console, as_json=json_output)
        return

    _batch_render_results(
        results,
        batch_infos,
        console,
        json_output=json_output,
        csv_output=csv_output,
        markdown=markdown,
        include_ecosystem=include_ecosystem,
        error_prefix=_ERROR_PREFIX,
    )
