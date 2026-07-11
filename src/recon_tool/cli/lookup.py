"""Lookup / discover command implementation: resolve, fuse, emit (panel/json/markdown/explain).

Extracted from cli.py (docs/roadmap.md god-file track). Plain command-logic
helpers; the Typer app and the thin @app.command wrappers stay in cli.py, which
imports this module and references the orchestrators through a small assignment
facade. Imports the shared cli helpers / formatter; never imports cli.py.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import typer

from recon_tool.cli.options import LookupOperationMode, LookupOptions
from recon_tool.cli.shared import fmt_exc as _fmt_exc
from recon_tool.cli.shared import lookup_validate
from recon_tool.exit_codes import (
    EXIT_INTERNAL,
    EXIT_NO_DATA,
    EXIT_VALIDATION,
)
from recon_tool.formatter import get_console, get_err_console

# Spinner messages. A lookup shuffles these and rotates through them while
# it waits, so the CLI feels alive without being gimmicky. They are grouped
# by what recon is actually doing (DNS, CT, identity endpoints, the
# inference layer, posture) plus a few that wink at the passive-only ethos;
# all stay honest about the method.
_STATUS_MESSAGES = (
    # DNS and records
    "Querying public DNS records...",
    "Following CNAME breadcrumbs...",
    "Letting DNS tell its side of the story...",
    "Reading the TXT record tea leaves...",
    "Asking the MX records who handles the mail...",
    "Checking the mail trail...",
    "Untangling the SPF include chain...",
    "Reading DMARC policy, strictly as published...",
    "Checking identity hints in the open...",
    # Certificate transparency
    "Sifting certificate transparency logs...",
    "Reading certificate history like a lab notebook...",
    "Clustering SAN sets into communities...",
    "Watching for certificate issuance bursts...",
    "Sorting yesterday's certificates from today's clues...",
    # Identity endpoints
    "Checking Microsoft's public tenant registry...",
    "Asking Google Workspace, no credentials required...",
    "Knocking politely on the OIDC discovery endpoint...",
    "Comparing tenant hints without crossing any lines...",
    # Fingerprinting / stack
    "Fingerprinting the SaaS stack...",
    "Looking for quiet SaaS fingerprints...",
    "Matching slugs against the catalog...",
    "Assembling the tech stack mosaic...",
    "Tracing domain verification trails...",
    "Turning public records into a careful sketch...",
    "Cataloging breadcrumbs without stepping on anything...",
    # The inference layer (a wink at the Bayesian core)
    "Updating priors, declining to overclaim...",
    "Propagating beliefs through the network...",
    "Widening the interval where evidence is thin...",
    "Letting absent evidence stay absent...",
    "Computing model-relative uncertainty bands...",
    "Counting clues before drawing conclusions...",
    "Keeping the confidence meter honest...",
    "Letting uncertainty keep its seat at the table...",
    # Posture and footprint
    "Scoring the email security posture...",
    "Mapping the organizational footprint...",
    "Extracting signal from the public noise...",
    "Building a public-footprint map...",
    "Separating strong signals from hallway echoes...",
    # Passive-only ethos
    "No credentials were harmed in this lookup...",
    "Strictly passive; keeping the footprint light...",
    "Reading only what was left out in the open...",
    "Observing from a respectful distance...",
    "Staying on the sidewalk, reading the signs...",
    "Taking notes from the public record...",
)


# How long each spinner message lingers before the next one rotates in.
_STATUS_ROTATE_SECONDS = 2.5


def _build_explanations(
    info: Any,
    results: list[Any],
) -> list[Any]:
    """Build ExplanationRecords for a TenantInfo using the explanation engine.

    Generates explanations for signals, insights, confidence, and observations.
    """
    from recon_tool.absence import evaluate_absence_signals, evaluate_positive_absence
    from recon_tool.collection_view import (
        collection_observable_evidence,
        collection_observable_info,
        collection_observable_results,
    )
    from recon_tool.email_security import signal_context_from_tenant_info, signal_context_metadata
    from recon_tool.explanation import (
        explain_confidence,
        explain_insights,
        explain_observations,
        explain_signals,
    )
    from recon_tool.merger import compute_evidence_confidence, compute_inference_confidence
    from recon_tool.models import ExplanationRecord
    from recon_tool.posture import analyze_posture, load_posture_rules
    from recon_tool.signals import evaluate_signals, load_signals

    info = collection_observable_info(info)
    observable_evidence = collection_observable_evidence(info)
    explanations: list[ExplanationRecord] = []

    context = signal_context_from_tenant_info(info)
    context_metadata = signal_context_metadata(context)
    signals = load_signals()
    signal_matches = evaluate_signals(context)

    # Third pass: absence signals + positive hardening observations
    absence_matches = evaluate_absence_signals(signal_matches, signals, frozenset(info.slugs))
    positive_matches = evaluate_positive_absence(signal_matches, signals, frozenset(info.slugs))
    all_signal_matches = signal_matches + absence_matches + positive_matches

    # Signal explanations
    signal_recs = explain_signals(
        all_signal_matches,
        signals,
        frozenset(info.slugs),
        context_metadata,
        observable_evidence,
        info.detection_scores,
    )
    explanations.extend(signal_recs)

    # Insight explanations
    insight_recs = explain_insights(
        list(info.insights),
        frozenset(info.slugs),
        frozenset(info.services),
        observable_evidence,
        info.detection_scores,
    )
    explanations.extend(insight_recs)

    # Confidence explanation
    if results:
        observable_results = collection_observable_results(results)
        evidence_conf = compute_evidence_confidence(observable_results)
        inference_conf = compute_inference_confidence(observable_results)
        conf_rec = explain_confidence(observable_results, evidence_conf, inference_conf, info.confidence)
        explanations.append(conf_rec)

    # Observation explanations
    observations = analyze_posture(info)
    posture_rules = load_posture_rules()
    obs_recs = explain_observations(observations, posture_rules, observable_evidence, info.detection_scores)
    explanations.extend(obs_recs)

    return explanations


async def _resolve_with_spinner(
    console: Any, validated: str, *, timeout: float, skip_ct: bool, quiet: bool, active_probes: bool = False
) -> tuple[Any, list[Any]]:
    """Resolve a tenant, showing a status spinner unless output is machine-readable."""
    from recon_tool.resolver import resolve_tenant

    if quiet:
        return await resolve_tenant(validated, timeout=timeout, skip_ct=skip_ct, active_probes=active_probes)

    coro = resolve_tenant(validated, timeout=timeout, skip_ct=skip_ct, active_probes=active_probes)
    # Spinner goes to stderr so it never contaminates the stdout data stream.
    return await _run_with_rotating_status(get_err_console(), coro)


async def _run_with_rotating_status(console: Any, coro: Any) -> Any:
    """Await ``coro`` while rotating spinner messages, so a slow lookup shows
    a shuffled sequence of status lines rather than one static message.

    The rotation is purely cosmetic: the awaited coroutine runs to completion
    regardless, and any exception it raises propagates unchanged. Falls back to
    a single static status if anything about the rotation goes wrong, so the
    spinner can never break a lookup.
    """
    import random

    order = list(_STATUS_MESSAGES)
    random.shuffle(order)
    task = asyncio.ensure_future(coro)
    with console.status(order[0]) as status:
        idx = 0
        while True:
            try:
                return await asyncio.wait_for(asyncio.shield(task), timeout=_STATUS_ROTATE_SECONDS)
            except TimeoutError:
                # The lookup is still running; advance to the next message.
                idx += 1
                try:
                    status.update(order[idx % len(order)])
                except Exception:  # a status-update failure must not abort the lookup
                    return await task


async def _resolve_cached(
    console: Any,
    validated: str,
    *,
    no_cache: bool,
    cache_ttl: int,
    timeout: float,
    skip_ct: bool,
    quiet: bool,
    active_probes: bool = False,
) -> Any:
    """Return a cached TenantInfo if present, else resolve fresh and cache it."""
    info: Any = None
    if not no_cache:
        from recon_tool.cache import cache_get

        cached = cache_get(validated, ttl=cache_ttl)
        if cached is not None:
            info = cached
    if info is None:
        info, _results = await _resolve_with_spinner(
            console, validated, timeout=timeout, skip_ct=skip_ct, quiet=quiet, active_probes=active_probes
        )
        if not no_cache:
            from recon_tool.cache import cache_put

            cache_put(validated, info)
    return info


async def _lookup_compare(
    console: Any,
    validated: str,
    domain: str,
    options: LookupOptions,
) -> None:
    """Resolve and diff against a saved snapshot (`--compare`)."""
    from pathlib import Path as _Path

    from recon_tool.delta import compute_delta, load_previous
    from recon_tool.formatter import format_delta_json, render_delta_panel, render_error, render_warning
    from recon_tool.models import ReconLookupError

    compare_file = options.compare_file
    if compare_file is None:
        render_error("--compare requires a snapshot path")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    try:
        previous = load_previous(_Path(compare_file))
    except (FileNotFoundError, ValueError) as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from None

    try:
        info, _results = await _resolve_with_spinner(
            console,
            validated,
            timeout=options.timeout,
            skip_ct=options.skip_ct,
            quiet=options.quiet,
            active_probes=options.active_probes,
        )
    except ReconLookupError as exc:
        render_warning(domain, exc)
        raise typer.Exit(code=EXIT_NO_DATA) from None
    except Exception as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from None

    delta = compute_delta(previous, info)
    if options.json_output:
        typer.echo(format_delta_json(delta))
    else:
        console.print(render_delta_panel(delta))


async def _lookup_chain(
    console: Any,
    validated: str,
    options: LookupOptions,
) -> None:
    """Follow related-domain breadcrumbs (`--chain`)."""
    from recon_tool.chain import chain_resolve
    from recon_tool.formatter import format_chain_json, render_chain_panel, render_error

    try:
        if not options.quiet:
            import random

            msg = random.choice(_STATUS_MESSAGES)  # noqa: S311
            with get_err_console().status(msg):
                report = await chain_resolve(
                    validated,
                    depth=options.chain_depth,
                    skip_ct=options.skip_ct,
                    active_probes=options.active_probes,
                )
        else:
            report = await chain_resolve(
                validated,
                depth=options.chain_depth,
                skip_ct=options.skip_ct,
                active_probes=options.active_probes,
            )
    except Exception as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from None

    if options.json_output:
        chain_dict = json.loads(format_chain_json(report))
        if options.show_explain:
            from recon_tool.formatter import format_explanations_list

            for i, domain_entry in enumerate(chain_dict.get("domains", [])):
                if i < len(report.results):
                    chain_info = report.results[i].info
                    explanations = _build_explanations(chain_info, [])
                    domain_entry["explanations"] = format_explanations_list(explanations)
                    if chain_info.merge_conflicts and chain_info.merge_conflicts.has_conflicts:
                        from recon_tool.models import serialize_conflicts

                        domain_entry["conflicts"] = serialize_conflicts(chain_info.merge_conflicts)
        typer.echo(json.dumps(chain_dict, indent=2))
    else:
        console.print(render_chain_panel(report))
        if options.show_explain:
            from recon_tool.formatter import render_explanations_panel

            for r in report.results:
                explanations = _build_explanations(r.info, [])
                if explanations:
                    console.print(render_explanations_panel(explanations))


async def _lookup_exposure(
    console: Any,
    validated: str,
    domain: str,
    options: LookupOptions,
) -> None:
    """Resolve (cache-aware) and render the exposure score (`--exposure`)."""
    from recon_tool.exposure import assess_exposure_from_info
    from recon_tool.formatter import format_exposure_json, render_error, render_exposure_panel, render_warning
    from recon_tool.models import ReconLookupError

    try:
        info_exp = await _resolve_cached(
            console,
            validated,
            no_cache=options.no_cache,
            cache_ttl=options.cache_ttl,
            timeout=options.timeout,
            skip_ct=options.skip_ct,
            quiet=options.quiet,
            active_probes=options.active_probes,
        )
        assessment = assess_exposure_from_info(info_exp)
        if options.json_output:
            typer.echo(format_exposure_json(assessment))
        else:
            console.print(render_exposure_panel(assessment))
    except ReconLookupError as exc:
        render_warning(domain, exc)
        raise typer.Exit(code=EXIT_NO_DATA) from None
    except Exception as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from None


async def _lookup_gaps(
    console: Any,
    validated: str,
    domain: str,
    options: LookupOptions,
) -> None:
    """Resolve (cache-aware) and render the detection-gap report (`--gaps`)."""
    from recon_tool.exposure import find_gaps_from_info
    from recon_tool.formatter import format_gaps_json, render_error, render_gaps_panel, render_warning
    from recon_tool.models import ReconLookupError

    try:
        info_gaps = await _resolve_cached(
            console,
            validated,
            no_cache=options.no_cache,
            cache_ttl=options.cache_ttl,
            timeout=options.timeout,
            skip_ct=options.skip_ct,
            quiet=options.quiet,
            active_probes=options.active_probes,
        )
        report = find_gaps_from_info(info_gaps)
        if options.json_output:
            typer.echo(format_gaps_json(report))
        else:
            console.print(render_gaps_panel(report))
    except ReconLookupError as exc:
        render_warning(domain, exc)
        raise typer.Exit(code=EXIT_NO_DATA) from None
    except Exception as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from None


def _lookup_apply_fusion(info: Any) -> Any:
    """Recompute slug posteriors and the Bayesian network marginals onto ``info``.

    Purely deterministic over the existing ``TenantInfo`` (no network calls), so
    it runs on both cache hits and misses when ``--fusion`` / ``--explain-dag``
    is set. ``--explain-dag`` implies ``--fusion`` because the DAG renderer needs
    the posteriors present.
    """
    from dataclasses import replace

    from recon_tool.bayesian import infer_from_tenant_info
    from recon_tool.collection_view import collection_observable_evidence
    from recon_tool.fusion import compute_slug_posteriors
    from recon_tool.models import NodeConflict, NodeEvidence, NodeUnitCounterfactual, PosteriorObservation

    bayesian_result = infer_from_tenant_info(info)
    bayesian_observations = tuple(
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
            evidence_ranked=tuple(
                NodeEvidence(
                    kind=e.kind,
                    name=e.name,
                    llr=e.llr,
                    influence_pct=e.influence_pct,
                )
                for e in p.evidence_ranked
            ),
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
        for p in bayesian_result.posteriors
    )
    return replace(
        info,
        slug_confidences=compute_slug_posteriors(collection_observable_evidence(info)),
        posterior_observations=bayesian_observations,
    )


async def _lookup_resolve_standard(
    console: Any,
    validated: str,
    options: LookupOptions,
) -> tuple[Any, list[Any]]:
    """Cache read, resolve on miss, apply fusion, write back. Returns (info, results)."""
    info: Any = None
    results: list[Any] = []
    if not options.no_cache:
        from recon_tool.cache import cache_get

        cached = cache_get(validated, ttl=options.cache_ttl)
        if cached is not None:
            info = cached

    cache_miss = info is None
    if cache_miss:
        info, results = await _resolve_with_spinner(
            console,
            validated,
            timeout=options.timeout,
            skip_ct=options.skip_ct,
            quiet=options.quiet,
            active_probes=options.active_probes,
        )

    if options.fusion or options.explain_dag:
        info = _lookup_apply_fusion(info)
    else:
        # --no-fusion: a cache hit may carry fusion fields written by an earlier
        # default-on run. Clear them so the opt-out is honored (fusion_enabled is
        # derived from posterior_observations downstream).
        from dataclasses import replace as _replace

        info = _replace(info, slug_confidences={}, posterior_observations=())

    # Cache hits don't write back: the entry hasn't changed except for fusion
    # output, which is recomputed on read anyway.
    if cache_miss and not options.no_cache:
        from recon_tool.cache import cache_put

        cache_put(validated, info)
    return info, results


def _lookup_compute_observations(info: Any, profile_name: str | None, show_posture: bool) -> tuple[Any, ...]:
    """Resolve the requested posture profile and compute posture observations."""
    from recon_tool.formatter import render_error

    profile = None
    if profile_name:
        from recon_tool.profiles import load_profile

        profile = load_profile(profile_name)
        if profile is None:
            from recon_tool.profiles import list_profiles

            names = ", ".join(p.name for p in list_profiles())
            render_error(f"Unknown profile {profile_name!r}. Available profiles: {names or '(none)'}")
            raise typer.Exit(code=EXIT_VALIDATION) from None

    observations: tuple[Any, ...] = ()
    if show_posture:
        from recon_tool.posture import analyze_posture
        from recon_tool.profiles import apply_profile, compute_baseline_anomalies

        raw_observations = analyze_posture(info)
        # Append vertical-baseline anomalies before profile reweighting so
        # profile boosts apply uniformly. Empty tuple when no profile or when the
        # profile has no expectations.
        anomalies = compute_baseline_anomalies(
            profile,
            info.slugs,
            tuple(cm.motif_name for cm in info.chain_motifs),
        )
        combined_obs = tuple(raw_observations) + anomalies
        observations = apply_profile(combined_obs, profile)
    return observations


def _lookup_emit_explain_dag(validated: str, info: Any, explain_dag_format: str) -> None:
    """Render the Bayesian evidence DAG in the requested format (`--explain-dag`)."""
    from recon_tool.bayesian import collection_masked_units, infer_from_tenant_info, load_network
    from recon_tool.bayesian_dag import render_dag_dot, render_dag_mermaid, render_dag_text
    from recon_tool.formatter import render_error

    network = load_network()
    inference = infer_from_tenant_info(info, network=network)
    fmt = (explain_dag_format or "text").lower()
    degraded = sorted(set(getattr(info, "degraded_sources", ()) or ()))
    masked = sorted(collection_masked_units(degraded, network=network))
    if degraded:
        degraded_text = ", ".join(degraded)
        masked_text = ", ".join(masked) if masked else "none"
        if fmt == "dot":
            provenance_prefix = f"// degraded_sources: {degraded_text}\n// collection_masked_units: {masked_text}\n"
        elif fmt == "mermaid":
            provenance_prefix = f"%% degraded_sources: {degraded_text}\n%% collection_masked_units: {masked_text}\n"
        else:
            provenance_prefix = (
                "Collection provenance:\n"
                f"- degraded_sources: {degraded_text}\n"
                f"- collection-masked units: {masked_text}\n\n"
            )
    else:
        provenance_prefix = ""
    if fmt == "dot":
        typer.echo(provenance_prefix + render_dag_dot(network, inference, domain=validated))
    elif fmt == "mermaid":
        typer.echo(provenance_prefix + render_dag_mermaid(network, inference, domain=validated))
    elif fmt == "text":
        typer.echo(provenance_prefix + render_dag_text(network, inference, domain=validated))
    else:
        render_error(f"--explain-dag-format must be 'text', 'dot', or 'mermaid', got {explain_dag_format!r}")
        raise typer.Exit(code=EXIT_VALIDATION) from None


def _lookup_emit_json(
    info: Any,
    results: list[Any],
    observations: tuple[Any, ...],
    *,
    show_posture: bool,
    show_explain: bool,
    include_unclassified: bool,
) -> None:
    """Emit the tenant dict as JSON, with optional posture and explanation blocks."""
    from recon_tool.formatter import format_posture_observations, format_tenant_dict

    tenant_dict = format_tenant_dict(info, include_unclassified=include_unclassified)
    if show_posture:
        tenant_dict["posture"] = format_posture_observations(observations)
    if show_explain:
        from recon_tool.collection_view import collection_observable_evidence
        from recon_tool.explanation import build_explanation_dag
        from recon_tool.formatter import format_explanations_list
        from recon_tool.models import serialize_conflicts

        explanations = _build_explanations(info, results)
        tenant_dict["explanations"] = format_explanations_list(explanations)
        # Structured provenance DAG for programmatic consumers. Lives
        # alongside the flat list; both are emitted so existing tooling doesn't
        # break.
        tenant_dict["explanation_dag"] = build_explanation_dag(explanations, collection_observable_evidence(info))
        if info.merge_conflicts and info.merge_conflicts.has_conflicts:
            tenant_dict["conflicts"] = serialize_conflicts(info.merge_conflicts)
    typer.echo(json.dumps(tenant_dict, indent=2))


def _lookup_emit_markdown(
    info: Any,
    results: list[Any],
    observations: tuple[Any, ...],
    *,
    show_posture: bool,
    show_explain: bool,
) -> None:
    """Emit the tenant report as Markdown, with optional posture and explanations."""
    from recon_tool.formatter import format_tenant_markdown
    from recon_tool.formatter.markdown import markdown_escape

    md = format_tenant_markdown(info)
    if show_posture and observations:
        md += "\n## Posture Analysis\n\n"
        for obs in observations:
            indicator = {"high": "●", "medium": "◐", "low": "○"}.get(obs.salience, "○")
            category = markdown_escape(obs.category)
            statement = markdown_escape(obs.statement)
            md += f"- {indicator} **[{category}]** {statement}\n"
        md += "\n"
    if show_explain:
        from recon_tool.formatter import format_explanations_markdown

        explanations = _build_explanations(info, results)
        md += "\n" + format_explanations_markdown(explanations)
    typer.echo(md)


def _lookup_emit_plain(info: Any, *, include_unclassified: bool) -> None:
    """Emit the tenant report as plain, linear, greppable text (no panel)."""
    from recon_tool.formatter import format_tenant_plain

    typer.echo(format_tenant_plain(info, include_unclassified=include_unclassified))


def _synthetic_source_results(info: Any) -> list[Any]:
    """Reconstruct minimal SourceResults from a cached TenantInfo.

    On a cache hit the raw SourceResult list isn't available (the cache stores
    TenantInfo, not source results), so the `--explain` status panel rebuilds
    what it can from ``info.sources`` (successes) and ``info.degraded_sources``
    (failures).
    """
    from recon_tool.models import SourceResult

    _m365_sources = {"oidc_discovery", "user_realm", "dns_records"}
    synthetic: list[SourceResult] = []
    for src_name in info.sources:
        synthetic.append(
            SourceResult(
                source_name=src_name,
                tenant_id=info.tenant_id if src_name == "oidc_discovery" else None,
                display_name=info.display_name if src_name == "user_realm" else None,
                auth_type=info.auth_type if src_name == "user_realm" else None,
                m365_detected=bool(info.tenant_id) and src_name in _m365_sources,
                dmarc_policy=info.dmarc_policy if src_name == "dns_records" else None,
            )
        )
    for deg in info.degraded_sources:
        synthetic.append(
            SourceResult(
                source_name=deg,
                error="unavailable during original lookup",
            )
        )
    return synthetic


def _lookup_emit_panel(
    console: Any,
    info: Any,
    results: list[Any],
    observations: tuple[Any, ...],
    *,
    show_services: bool,
    show_domains: bool,
    verbose: bool,
    show_explain: bool,
    show_sources: bool,
    show_posture: bool,
    confidence_mode: str,
) -> None:
    """Render the default human-readable panel, plus optional sources/posture/explain."""
    from recon_tool.collection_view import collection_observable_results
    from recon_tool.formatter import render_sources_detail, render_tenant_panel

    visible_results = collection_observable_results(results)

    console.print(
        render_tenant_panel(
            info,
            show_services=show_services,
            show_domains=show_domains,
            verbose=verbose,
            explain=show_explain,
            confidence_mode=confidence_mode,
        )
    )

    if show_sources:
        console.print(render_sources_detail(visible_results))

    # Posture panel after main output
    if show_posture and observations:
        from recon_tool.formatter import render_posture_panel

        posture_panel = render_posture_panel(observations)
        if posture_panel:
            console.print(posture_panel)

    # Explanations panel after posture
    if show_explain:
        from recon_tool.formatter import render_explanations_panel, render_source_status_panel

        # U1: always render per-source status under --explain so users
        # can see which sources succeeded, which failed, and why. Previously this
        # was only available via --verbose.
        status_results: list[Any] = visible_results
        if not status_results and info is not None:
            status_results = _synthetic_source_results(info)

        status_panel = render_source_status_panel(status_results)
        if status_panel:
            console.print(status_panel)

        explanations = _build_explanations(info, visible_results)
        if explanations:
            console.print(render_explanations_panel(explanations))


async def _lookup_standard(
    console: Any,
    validated: str,
    domain: str,
    options: LookupOptions,
) -> None:
    """The default lookup path: resolve, fuse, then emit DAG / JSON / Markdown / panel."""
    from recon_tool.formatter import render_error, render_verbose_sources, render_warning
    from recon_tool.models import ReconLookupError

    try:
        info, results = await _lookup_resolve_standard(
            console,
            validated,
            options=options,
        )

        if options.verbose:
            from recon_tool.collection_view import collection_observable_results

            render_verbose_sources(collection_observable_results(results))

        observations = _lookup_compute_observations(info, options.profile_name, options.show_posture)

        if options.explain_dag:
            _lookup_emit_explain_dag(validated, info, options.explain_dag_format)
            return
        if options.json_output:
            _lookup_emit_json(
                info,
                results,
                observations,
                show_posture=options.show_posture,
                show_explain=options.show_explain,
                include_unclassified=options.include_unclassified,
            )
            return
        if options.markdown:
            _lookup_emit_markdown(
                info,
                results,
                observations,
                show_posture=options.show_posture,
                show_explain=options.show_explain,
            )
            return
        if options.plain:
            _lookup_emit_plain(info, include_unclassified=options.include_unclassified)
            return

        _lookup_emit_panel(
            console,
            info,
            results,
            observations,
            show_services=options.show_services,
            show_domains=options.show_domains,
            verbose=options.verbose,
            show_explain=options.show_explain,
            show_sources=options.show_sources,
            show_posture=options.show_posture,
            confidence_mode=options.confidence_mode,
        )
    except typer.Exit:
        # Deliberate control-flow exits (an unknown --profile or a bad
        # --explain-dag-format raise typer.Exit(EXIT_VALIDATION) from inside the
        # try). typer.Exit subclasses Exception, so without this it would be
        # caught below, reclassified to EXIT_INTERNAL, and print a bare "Exit".
        raise
    except ReconLookupError as exc:
        render_warning(domain, exc)
        raise typer.Exit(code=EXIT_NO_DATA) from None
    except Exception as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from None


async def lookup(
    domain: str,
    options: LookupOptions,
) -> None:
    """Async lookup implementation.

    A thin dispatcher: validate the domain and normalized option set, then hand
    off to the mode helper for compare / chain / exposure / gaps, or to the
    standard panel path.
    """
    console = get_console()

    validated = lookup_validate(domain, options=options)

    if options.operation_mode is LookupOperationMode.COMPARE:
        await _lookup_compare(console, validated, domain, options)
        return

    if options.operation_mode is LookupOperationMode.CHAIN:
        await _lookup_chain(console, validated, options)
        return

    if options.operation_mode is LookupOperationMode.EXPOSURE:
        await _lookup_exposure(console, validated, domain, options)
        return

    if options.operation_mode is LookupOperationMode.GAPS:
        await _lookup_gaps(console, validated, domain, options)
        return

    await _lookup_standard(console, validated, domain, options)
