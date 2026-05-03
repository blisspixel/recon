"""CNAME chain motif library (v1.7+).

A motif is an ordered sequence of markers expected to appear in a CNAME
chain. Each marker matches when ANY of its substrings appears in a
hop's hostname. A motif fires only when every marker matches in chain
order — intermediate hops between markers are allowed.

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
from typing import Any

import yaml

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

_VALID_CONFIDENCE = {"high", "medium", "low"}


@dataclass(frozen=True)
class _MotifMarker:
    """A single position in a motif's chain. Matches a hop when any of
    its substrings is contained in the hop's hostname."""

    name: str
    patterns: tuple[str, ...]


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
    ``chain_motifs`` in --json (v1.7+).
    """

    motif_name: str
    display_name: str
    confidence: str
    subdomain: str
    chain: tuple[str, ...]


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
        logger.warning(
            "Motif %r has invalid confidence %r in %s — skipped", name, confidence, source
        )
        return None
    description = raw.get("description") or ""
    if not isinstance(description, str):
        description = ""
    chain_raw = raw.get("chain")
    if not isinstance(chain_raw, list) or not chain_raw:
        return None
    if len(chain_raw) > MOTIF_CHAIN_HARD_CAP:
        logger.warning(
            "Motif %r has %d markers (cap %d) in %s — skipped",
            name,
            len(chain_raw),
            MOTIF_CHAIN_HARD_CAP,
            source,
        )
        return None
    markers: list[_MotifMarker] = []
    for m_raw in chain_raw:
        if not isinstance(m_raw, dict):
            return None
        m_name = m_raw.get("name")
        m_match = m_raw.get("match")
        if not isinstance(m_name, str) or not m_name:
            return None
        if not isinstance(m_match, list) or not m_match:
            return None
        patterns: list[str] = []
        for p in m_match:
            if not isinstance(p, str):
                continue
            p_clean = p.strip().lower()
            if p_clean:
                patterns.append(p_clean)
            if len(patterns) >= MAX_PATTERNS_PER_MARKER:
                break
        if not patterns:
            return None
        markers.append(_MotifMarker(name=m_name, patterns=tuple(patterns)))
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
        text = path.read_text(encoding="utf-8")
        loaded = yaml.safe_load(text)
    except (yaml.YAMLError, OSError) as exc:
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
_USER_PATHS: tuple[Path, ...] = (Path.home() / ".recon" / "motifs.yaml",)


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
    for path in (_BUILTIN_PATH, *_USER_PATHS):
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
            hop_lower = chain[chain_idx].lower()
            if any(p in hop_lower for p in marker.patterns):
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
