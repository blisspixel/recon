"""Deterministic replay of cached DNS records through fingerprint rules.

The MCP ephemeral-fingerprint workflow must remain network-free: a prior DNS
lookup retains the bounded raw record values needed to evaluate a newly loaded
catalog, and this module projects only those retained observations through the
same record-type matchers used by live collection.  It does not reconstruct
records that were not cached or turn an unavailable collection channel into a
negative or positive observation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import replace
from typing import TYPE_CHECKING

from recon_tool.fingerprints import (
    Detection,
    filter_shadowed_matches,
    get_cname_patterns,
    get_m365_slugs,
    get_mx_patterns,
    get_ns_patterns,
    get_spf_patterns,
    get_txt_patterns,
    match_txt_all,
)
from recon_tool.models import EvidenceRecord, SourceResult
from recon_tool.regex_safety import compile_regex
from recon_tool.source_status import ObservationChannel, SourceStatus
from recon_tool.sources.dns_base import DetectionCtx

if TYPE_CHECKING:
    from recon_tool.fingerprints import Fingerprint

_REPLAY_CHANNELS: dict[str, ObservationChannel] = {
    "TXT": "apex_txt",
    "MX": "mx",
    "NS": "ns",
    "CNAME": "cname",
}

# A DNS name is at most 253 characters. This matches the live CNAME detector's
# defensive input bound before a catalog regex is evaluated.
_MAX_CNAME_MATCH_LEN = 255


def _record_match(
    ctx: DetectionCtx,
    record_type: str,
    value: str,
    detections: tuple[Detection, ...],
    *,
    regex: bool = False,
) -> None:
    """Apply first-match, longest-pattern semantics to one cached record."""
    candidate = value.lower()[:_MAX_CNAME_MATCH_LEN] if regex else value.lower()
    for detection in sorted(detections, key=lambda item: -len(item.pattern)):
        if regex:
            compiled = compile_regex(detection.pattern, re.IGNORECASE)
            matched = compiled is not None and compiled.search(candidate) is not None
        else:
            matched = detection.pattern in candidate
        if not matched:
            continue
        ctx.add(
            detection.name,
            detection.slug,
            source_type=record_type,
            raw_value=value,
        )
        ctx.record_fp_match(detection.slug, record_type.lower(), detection.pattern)
        return


def _replay_txt(ctx: DetectionCtx, value: str) -> None:
    """Replay apex TXT and SPF catalog rules with live-detector semantics."""
    matches = match_txt_all(value, get_txt_patterns())
    if matches:
        first = matches[0]
        ctx.add(first.name, first.slug, source_type="TXT", raw_value=value)
        for match in matches:
            if match.slug == first.slug:
                ctx.record_fp_match(match.slug, "txt", match.pattern)

    lowered = value.lower()
    if not lowered.startswith("v=spf1"):
        return
    spf_matches = [rule for rule in get_spf_patterns() if rule.pattern.lower() in lowered]
    for match in filter_shadowed_matches(spf_matches):
        ctx.add(match.name, match.slug, source_type="SPF", raw_value=value)
        ctx.record_fp_match(match.slug, "spf", match.pattern)


def _replayed_context(result: SourceResult) -> DetectionCtx:
    """Build fingerprint-only detections from observable cached DNS records."""
    ctx = DetectionCtx()
    status = SourceStatus.from_degraded_sources(result.degraded_sources)
    if result.error is not None or result.source_unavailable or status.whole_dns_unavailable:
        return ctx

    records = sorted(
        {(record_type.upper(), value) for record_type, value in result.raw_dns_records},
        key=lambda item: (item[0], item[1]),
    )
    for record_type, value in records:
        channel = _REPLAY_CHANNELS.get(record_type)
        if channel is None or status.channel_unavailable(channel):
            continue
        if record_type == "TXT":
            _replay_txt(ctx, value)
        elif record_type == "MX":
            _record_match(ctx, "MX", value, get_mx_patterns())
        elif record_type == "NS":
            _record_match(ctx, "NS", value, get_ns_patterns())
        elif record_type == "CNAME":
            _record_match(ctx, "CNAME", value, get_cname_patterns(), regex=True)
    ctx.enforce_match_mode_all()
    return ctx


def replay_cached_dns_fingerprints(result: SourceResult) -> SourceResult:
    """Return ``result`` plus fingerprint matches from its cached DNS values.

    Original evidence and detector fields remain intact. Added values are
    sorted and exact evidence occurrences are deduplicated, so repeated replay
    is idempotent. The source cache may continue retaining the original result;
    callers can merge this projection without changing the lookup freshness
    timestamp or the immutable collection record.
    """
    if not result.raw_dns_records:
        return result

    ctx = _replayed_context(result)
    if not ctx.services and not ctx.slugs and not ctx.evidence:
        return result

    evidence: list[EvidenceRecord] = list(result.evidence)
    seen = set(evidence)
    for occurrence in sorted(
        ctx.evidence,
        key=lambda item: (item.source_type, item.raw_value, item.slug, item.rule_name),
    ):
        if occurrence not in seen:
            seen.add(occurrence)
            evidence.append(occurrence)

    return replace(
        result,
        detected_services=tuple(sorted(set(result.detected_services) | ctx.services)),
        detected_slugs=tuple(sorted(set(result.detected_slugs) | ctx.slugs)),
        m365_detected=result.m365_detected or ctx.m365,
        evidence=tuple(evidence),
    )


def remove_fingerprint_projection(
    result: SourceResult,
    fingerprints: Iterable[Fingerprint],
) -> SourceResult:
    """Remove detections contributed by the specified dynamic fingerprints.

    A session fingerprint may already have participated in the live lookup that
    populated the MCP cache. Clearing the catalog must therefore remove its
    stored projection as well as future replay matches. Raw DNS observations and
    every unrelated evidence occurrence remain unchanged, so the same records
    can be evaluated again after a later injection.
    """
    removed = tuple(fingerprints)
    if not removed:
        return result

    identities = {(fingerprint.slug, fingerprint.name) for fingerprint in removed}
    evidence = tuple(
        occurrence for occurrence in result.evidence if (occurrence.slug, occurrence.rule_name) not in identities
    )
    remaining_slugs = {occurrence.slug for occurrence in evidence}
    remaining_names = {occurrence.rule_name for occurrence in evidence}
    removed_slugs = {fingerprint.slug for fingerprint in removed}
    removed_names = {fingerprint.name for fingerprint in removed}
    slugs = {slug for slug in result.detected_slugs if slug not in removed_slugs or slug in remaining_slugs}
    services = {
        service for service in result.detected_services if service not in removed_names or service in remaining_names
    }
    if (
        evidence == result.evidence
        and slugs == set(result.detected_slugs)
        and services == set(result.detected_services)
    ):
        return result

    return replace(
        result,
        detected_services=tuple(sorted(services)),
        detected_slugs=tuple(sorted(slugs)),
        m365_detected=result.m365_detected and not get_m365_slugs().isdisjoint(slugs),
        evidence=evidence,
    )
