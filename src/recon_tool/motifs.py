"""CNAME chain motif library.

A motif is an ordered sequence of markers expected to appear in a CNAME
chain. Built-in markers match hostname suffixes at DNS-label boundaries.
Custom markers can explicitly select suffix matching or retain historical
substring matching. Every marker must match in order; intermediate hops
between markers are allowed.

Motifs name observable proxy / CDN / origin shapes. They never claim
ownership ("co-hosted on" is observable; "same owner" is not).

Loaded from ``recon_tool/data/motifs.yaml`` (built-in) plus
``~/.recon/motifs.yaml`` (user, additive only). All matching is
deterministic and bounded.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from recon_tool.validator import host_has_suffix, is_domain_shaped

logger = logging.getLogger(__name__)

__all__ = [
    "MAX_MOTIFS",
    "MAX_PATTERNS_PER_MARKER",
    "MOTIF_CHAIN_HARD_CAP",
    "ChainMotif",
    "ChainMotifMatch",
    "load_motifs",
    "match_chain_motifs",
]

# Hard cap on motif chain length (per roadmap).
MOTIF_CHAIN_HARD_CAP = 4
# Hard cap on motif catalog size — prevents pathological YAML from blowing up runtime.
MAX_MOTIFS = 200
# Hard cap on substrings per marker.
MAX_PATTERNS_PER_MARKER = 12
# Hard cap on each built-in or custom motif YAML document before parsing.
_MAX_MOTIF_YAML_BYTES = 1024 * 1024

_VALID_CONFIDENCE = {"high", "medium", "low"}


@dataclass(frozen=True)
class _MotifMarker:
    """A chain position with explicit hostname-suffix or substring semantics."""

    name: str
    patterns: tuple[str, ...]
    match_mode: Literal["substring", "dns_suffix"] = "substring"


@dataclass(frozen=True)
class ChainMotif:
    """A loaded, validated chain motif.

    The motif fires when its ``markers`` are all present, in order,
    somewhere in a CNAME chain. Extra hops between matched markers are
    allowed.
    """

    name: str
    display_name: str
    description: str
    confidence: str
    markers: tuple[_MotifMarker, ...]


@dataclass(frozen=True)
class ChainMotifMatch:
    """One observed motif firing on a specific subdomain's CNAME chain.

    ``chain`` is the ordered subset of hops that matched the motif's
    markers — not the full original chain. Surfaced under
    ``chain_motifs`` in --json.
    """

    motif_name: str
    display_name: str
    confidence: str
    subdomain: str
    chain: tuple[str, ...]


def _hostname(value: str) -> str | None:
    """Normalize one ASCII hostname, rejecting malformed or oversized labels."""
    name = value.lower().removesuffix(".")
    if name != name.strip() or name.endswith(".") or len(name) > 253 or not is_domain_shaped(name):
        return None
    return name if all(len(label) <= 63 for label in name.split(".")) else None


def _marker_patterns(raw: list[Any], *, dns_suffix: bool) -> tuple[str, ...] | None:
    """Validate and cap patterns under the marker's declared grammar."""
    patterns: list[str] = []
    for p in raw:
        if not isinstance(p, str):
            if dns_suffix:
                return None
            continue
        p_clean = p.strip().lower()
        if dns_suffix:
            normalized = _hostname(p_clean)
            if normalized is None:
                return None
            p_clean = normalized
        if p_clean:
            patterns.append(p_clean)
        if len(patterns) >= MAX_PATTERNS_PER_MARKER:
            break
    return tuple(patterns) if patterns else None


def _parse_motif_marker(m_raw: Any) -> _MotifMarker | None:
    """Validate one chain marker; rejection invalidates the complete motif."""
    if not isinstance(m_raw, dict):
        return None
    m_name = m_raw.get("name")
    m_match = m_raw.get("match")
    if not isinstance(m_name, str) or not m_name:
        return None
    if not isinstance(m_match, list) or not m_match:
        return None
    mode = m_raw.get("match_mode", "substring")
    if mode not in ("substring", "dns_suffix"):
        return None
    patterns = _marker_patterns(m_match, dns_suffix=mode == "dns_suffix")
    if not patterns:
        return None
    return _MotifMarker(
        name=m_name,
        patterns=patterns,
        match_mode="dns_suffix" if mode == "dns_suffix" else "substring",
    )


def _validate_motif(raw: Any, source: str) -> ChainMotif | None:
    if not isinstance(raw, dict):
        return None
    name = raw.get("name")
    display_name = raw.get("display_name")
    if not isinstance(name, str) or not name:
        return None
    if not isinstance(display_name, str) or not display_name:
        return None
    confidence = raw.get("confidence", "medium")
    if confidence not in _VALID_CONFIDENCE:
        logger.warning("Motif %r has invalid confidence %r in %s; skipped", name, confidence, source)
        return None
    description = raw.get("description") or ""
    if not isinstance(description, str):
        description = ""
    chain_raw = raw.get("chain")
    if not isinstance(chain_raw, list) or not chain_raw:
        return None
    if len(chain_raw) > MOTIF_CHAIN_HARD_CAP:
        logger.warning(
            "Motif %r has %d markers (cap %d) in %s; skipped",
            name,
            len(chain_raw),
            MOTIF_CHAIN_HARD_CAP,
            source,
        )
        return None
    markers: list[_MotifMarker] = []
    for m_raw in chain_raw:
        marker = _parse_motif_marker(m_raw)
        if marker is None:
            return None
        markers.append(marker)
    return ChainMotif(
        name=name,
        display_name=display_name,
        description=description,
        confidence=confidence,
        markers=tuple(markers),
    )


def _load_from_path(path: Path) -> list[ChainMotif]:
    if not path.exists():
        return []
    try:
        stat = path.stat()
        if stat.st_size > _MAX_MOTIF_YAML_BYTES:
            logger.warning("Motif file %s exceeds %d bytes, skipped", path, _MAX_MOTIF_YAML_BYTES)
            return []
        text = path.read_text(encoding="utf-8")
        loaded = yaml.safe_load(text)
    except (yaml.YAMLError, OSError, RecursionError) as exc:
        logger.warning("Failed to load motifs from %s: %s", path, exc)
        return []
    raw_list: list[Any]
    if isinstance(loaded, dict) and "motifs" in loaded:
        raw_motifs = loaded["motifs"]
        raw_list = raw_motifs if isinstance(raw_motifs, list) else []
    elif isinstance(loaded, list):
        raw_list = loaded
    else:
        return []
    out: list[ChainMotif] = []
    source = str(path)
    for entry in raw_list:
        m = _validate_motif(entry, source)
        if m is not None:
            out.append(m)
        if len(out) >= MAX_MOTIFS:
            break
    return out


_BUILTIN_PATH = Path(__file__).parent / "data" / "motifs.yaml"


def _user_paths() -> tuple[Path, ...]:
    """User motif files, in the config dir (RECON_CONFIG_DIR / legacy / XDG)."""
    from recon_tool.paths import config_dir

    return (config_dir() / "motifs.yaml",)


@dataclass
class _MotifCacheState:
    motifs: tuple[ChainMotif, ...] | None = None


_cache_state = _MotifCacheState()


def load_motifs(reload: bool = False) -> tuple[ChainMotif, ...]:
    """Return the built-in + user motif catalog.

    User motifs from ``~/.recon/motifs.yaml`` extend the catalog but
    cannot override built-ins by name (additive-only invariant).
    Cached after first call; pass ``reload=True`` to refresh after a
    user-config change.
    """
    if not reload and _cache_state.motifs is not None:
        return _cache_state.motifs
    motifs: list[ChainMotif] = []
    seen_names: set[str] = set()
    for path in (_BUILTIN_PATH, *_user_paths()):
        for m in _load_from_path(path):
            if m.name in seen_names:
                continue
            seen_names.add(m.name)
            motifs.append(m)
            if len(motifs) >= MAX_MOTIFS:
                break
        if len(motifs) >= MAX_MOTIFS:
            break
    _cache_state.motifs = tuple(motifs)
    return _cache_state.motifs


def _marker_matches(marker: _MotifMarker, hop: str) -> bool:
    """Apply the declared grammar without guessing a custom marker's meaning."""
    if marker.match_mode == "substring":
        return any(pattern in hop.lower() for pattern in marker.patterns)
    hostname = _hostname(hop)
    return hostname is not None and any(host_has_suffix(hostname, pattern) for pattern in marker.patterns)


def _match_motif(motif: ChainMotif, chain: list[str]) -> tuple[str, ...] | None:
    """Walk the chain, looking for an ordered subsequence that satisfies
    every marker in turn.

    Returns the matched hops on success, or None when any marker has
    nowhere left in the chain to match.
    """
    matched_hops: list[str] = []
    chain_idx = 0
    for marker in motif.markers:
        found = False
        while chain_idx < len(chain):
            if _marker_matches(marker, chain[chain_idx]):
                matched_hops.append(chain[chain_idx])
                chain_idx += 1
                found = True
                break
            chain_idx += 1
        if not found:
            return None
    return tuple(matched_hops)


def match_chain_motifs(
    chain: list[str],
    motifs: tuple[ChainMotif, ...],
    *,
    subdomain: str = "",
) -> list[ChainMotifMatch]:
    """Return every motif that fires on ``chain``.

    Empty list when no motif matches, when the chain is empty, or when
    the catalog is empty. Order follows catalog order (which follows
    YAML order — stable across runs).
    """
    if not chain or not motifs:
        return []
    out: list[ChainMotifMatch] = []
    for motif in motifs:
        matched = _match_motif(motif, chain)
        if matched is None:
            continue
        out.append(
            ChainMotifMatch(
                motif_name=motif.name,
                display_name=motif.display_name,
                confidence=motif.confidence,
                subdomain=subdomain,
                chain=matched,
            )
        )
    return out
