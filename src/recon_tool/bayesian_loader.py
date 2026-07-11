"""Bayesian-network YAML loading, parsing, and topology validation.

Extracted from ``bayesian.py`` (docs/roadmap.md god-file track). Builds and
validates a ``BayesianNetwork`` from ``data/bayesian_network.yaml`` and applies
prior overrides. Imports the dataclasses from ``bayesian_models``; imported by
``bayesian.py`` (the inference engine), never the reverse.
"""

from __future__ import annotations

import logging
import math
from dataclasses import replace
from itertools import product
from pathlib import Path
from typing import Any

import yaml

from recon_tool.bayesian_models import BayesianNetwork, CalibrationSettings, Evidence, Node

logger = logging.getLogger(__name__)


# Default file paths. Operators can pass alternates to ``load_network``
# / ``load_priors_override`` for testing.
_DEFAULT_NETWORK_PATH = Path(__file__).resolve().parent / "data" / "bayesian_network.yaml"


def load_network(path: Path | None = None) -> BayesianNetwork:
    """Load and validate the Bayesian network YAML.

    Raises ``ValueError`` for malformed schema (unknown parents,
    missing CPT entries, cycles, probabilities outside [0, 1]).
    """
    target = path or _DEFAULT_NETWORK_PATH
    raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"bayesian_network: expected mapping at top level, got {type(raw).__name__}")

    version = raw.get("version")
    if version != 1:
        raise ValueError(f"bayesian_network: unsupported schema version {version!r}")
    calibration = _parse_calibration(raw.get("calibration"))

    raw_nodes = raw.get("nodes")
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise ValueError("bayesian_network: 'nodes' must be a non-empty list")

    nodes: list[Node] = []
    seen_names: set[str] = set()
    for raw_node in raw_nodes:
        nodes.append(_parse_network_node(raw_node, seen_names))

    # Validate: parents reference known nodes, DAG, CPT covers all parent assignments.
    _validate_topology(nodes)

    return BayesianNetwork(version=version, nodes=tuple(nodes), calibration=calibration)


def _parse_calibration(raw: Any) -> CalibrationSettings:
    """Validate top-level uncertainty-band display settings, with defaults."""
    defaults = CalibrationSettings()
    if raw is None:
        return defaults
    if not isinstance(raw, dict):
        raise ValueError("bayesian_network: 'calibration' must be a mapping")

    def _positive_number(key: str, default: float) -> float:
        value = raw.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(f"bayesian_network.calibration.{key}: expected positive number")
        value = float(value)
        if not math.isfinite(value) or value <= 0.0:
            raise ValueError(f"bayesian_network.calibration.{key}: expected positive finite number")
        return value

    return CalibrationSettings(
        min_n_eff=_positive_number("min_n_eff", defaults.min_n_eff),
        evidence_n_eff_contrib=_positive_number("evidence_n_eff_contrib", defaults.evidence_n_eff_contrib),
        conflict_n_eff_penalty=_positive_number("conflict_n_eff_penalty", defaults.conflict_n_eff_penalty),
    )


def _parse_node_prior_cpt(
    name: str, parents: tuple[str, ...], prior_raw: Any, cpt_raw: Any
) -> tuple[float | None, dict[str, float]]:
    """Validate a node's prior (root) or CPT (non-root). Raises ValueError."""
    if not parents:
        if not isinstance(prior_raw, int | float):
            raise ValueError(f"bayesian_network[{name}]: root node requires numeric 'prior'")
        prior = float(prior_raw)
        if not 0.0 < prior < 1.0:
            raise ValueError(f"bayesian_network[{name}]: prior {prior} outside (0, 1)")
        return prior, {}

    if not isinstance(cpt_raw, dict) or not cpt_raw:
        raise ValueError(f"bayesian_network[{name}]: node with parents requires 'cpt'")
    cpt: dict[str, float] = {}
    for k, v in cpt_raw.items():
        if not isinstance(k, str) or not isinstance(v, int | float):
            raise ValueError(f"bayesian_network[{name}]: cpt entries must be str→float")
        if not 0.0 < float(v) < 1.0:
            raise ValueError(f"bayesian_network[{name}]: cpt value {v} outside (0, 1)")
        cpt[k] = float(v)
    return None, cpt


def _parse_node_evidence(name: str, evidence_raw: Any) -> tuple[Evidence, ...]:
    """Validate a node's evidence bindings. Raises ValueError on a bad entry."""
    if not isinstance(evidence_raw, list):
        raise ValueError(f"bayesian_network[{name}]: 'evidence' must be a list")
    evidence: list[Evidence] = []
    for entry in evidence_raw:
        if not isinstance(entry, dict):
            raise ValueError(f"bayesian_network[{name}]: evidence entries must be mappings")
        slug = entry.get("slug")
        signal = entry.get("signal")
        if (slug is None) == (signal is None):
            raise ValueError(f"bayesian_network[{name}]: evidence entry must specify exactly one of 'slug' / 'signal'")
        kind = "slug" if slug else "signal"
        obs_name = slug if slug else signal
        if not isinstance(obs_name, str) or not obs_name:
            raise ValueError(f"bayesian_network[{name}]: evidence kind={kind} missing name")
        lik = entry.get("likelihood")
        if not isinstance(lik, list) or len(lik) != 2 or not all(isinstance(x, int | float) for x in lik):
            raise ValueError(f"bayesian_network[{name}/{obs_name}]: 'likelihood' must be [float, float]")
        lp, la = float(lik[0]), float(lik[1])
        if not (0.0 < lp < 1.0) or not (0.0 < la < 1.0):
            raise ValueError(f"bayesian_network[{name}/{obs_name}]: likelihoods must be strictly in (0, 1)")
        raw_group = entry.get("group")
        if raw_group is not None and not (isinstance(raw_group, str) and raw_group):
            raise ValueError(f"bayesian_network[{name}/{obs_name}]: 'group' must be a non-empty string")
        evidence.append(
            Evidence(kind=kind, name=obs_name, likelihood_present=lp, likelihood_absent=la, group=raw_group)
        )
    return tuple(evidence)


def _parse_network_node(raw_node: Any, seen_names: set[str]) -> Node:
    """Validate one node mapping and return a frozen Node. Raises ValueError.

    Mutates ``seen_names`` to enforce unique node names across the network.
    """
    if not isinstance(raw_node, dict):
        raise ValueError("bayesian_network: each node must be a mapping")
    name = raw_node.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("bayesian_network: node missing required 'name'")
    if name in seen_names:
        raise ValueError(f"bayesian_network: duplicate node name {name!r}")
    seen_names.add(name)

    description = raw_node.get("description") or ""
    if not isinstance(description, str):
        raise ValueError(f"bayesian_network[{name}]: 'description' must be a string")

    parents_raw = raw_node.get("parents") or []
    if not isinstance(parents_raw, list) or not all(isinstance(p, str) for p in parents_raw):
        raise ValueError(f"bayesian_network[{name}]: 'parents' must be a list of strings")
    parents: tuple[str, ...] = tuple(parents_raw)

    prior, cpt = _parse_node_prior_cpt(name, parents, raw_node.get("prior"), raw_node.get("cpt") or {})
    evidence = _parse_node_evidence(name, raw_node.get("evidence") or [])
    missingness = _parse_missingness(name, raw_node.get("missingness"))
    group_absence = _parse_group_absence(name, raw_node.get("group_absence"), evidence, missingness)

    return Node(
        name=name,
        description=description,
        parents=parents,
        prior=prior,
        cpt=cpt,
        evidence=evidence,
        missingness=missingness,
        group_absence=group_absence,
    )


def _parse_missingness(name: str, raw: Any) -> str:
    """Validate the optional node ``missingness`` field (default hideable)."""
    if raw is None:
        return "hideable"
    if raw not in ("hideable", "declarative"):
        raise ValueError(f"bayesian_network[{name}]: 'missingness' must be 'hideable' or 'declarative'")
    return raw


def _parse_group_absence(
    name: str, raw: Any, evidence: tuple[Evidence, ...], missingness: str
) -> tuple[tuple[str, float, float], ...]:
    """Validate ``group_absence``: per-group [P(no member|present), P(no member|absent)].

    Only meaningful for declarative nodes; each referenced group must exist
    among the node's bindings, and each likelihood must be strictly in (0, 1).
    """
    grouped = {ev.group for ev in evidence if ev.group}
    if raw is None:
        # A declarative node with grouped bindings but no group_absence treats each
        # group's absence as uninformative (LR=1), quietly weakening the
        # "absence is evidence" contract. Surface it so it stays a deliberate choice.
        if missingness == "declarative" and grouped:
            logger.warning(
                "bayesian_network[%s]: declarative node has grouped bindings %s but no "
                "group_absence; their absence is treated as uninformative (LR=1)",
                name,
                ", ".join(sorted(grouped)),
            )
        return ()
    if missingness != "declarative":
        raise ValueError(f"bayesian_network[{name}]: 'group_absence' is only valid on declarative nodes")
    if not isinstance(raw, dict):
        raise ValueError(f"bayesian_network[{name}]: 'group_absence' must be a mapping")
    known_groups = grouped
    out: list[tuple[str, float, float]] = []
    for group, pair in raw.items():
        if group not in known_groups:
            raise ValueError(f"bayesian_network[{name}]: group_absence group {group!r} has no bindings")
        if not isinstance(pair, list) or len(pair) != 2 or not all(isinstance(x, int | float) for x in pair):
            raise ValueError(f"bayesian_network[{name}/{group}]: group_absence must be [float, float]")
        lp, la = float(pair[0]), float(pair[1])
        if not (0.0 < lp < 1.0) or not (0.0 < la < 1.0):
            raise ValueError(f"bayesian_network[{name}/{group}]: group_absence likelihoods must be in (0, 1)")
        out.append((group, lp, la))
    uncovered = sorted(known_groups - {g for g, _, _ in out})
    if uncovered:
        logger.warning(
            "bayesian_network[%s]: declarative node groups %s have no group_absence entry; "
            "their absence is treated as uninformative (LR=1)",
            name,
            ", ".join(uncovered),
        )
    return tuple(out)


def _validate_topology(nodes: list[Node]) -> None:
    name_to_node = {n.name: n for n in nodes}

    # Parent references must resolve.
    for n in nodes:
        for p in n.parents:
            if p not in name_to_node:
                raise ValueError(f"bayesian_network[{n.name}]: parent {p!r} not defined")

    # No cycles. Topological sort via Kahn.
    incoming: dict[str, set[str]] = {n.name: set(n.parents) for n in nodes}
    queue: list[str] = [n for n, p in incoming.items() if not p]
    visited: list[str] = []
    while queue:
        cur = queue.pop(0)
        visited.append(cur)
        for n in nodes:
            if cur in incoming[n.name]:
                incoming[n.name].discard(cur)
                if not incoming[n.name]:
                    queue.append(n.name)
    if len(visited) != len(nodes):
        unresolved = [n for n, ps in incoming.items() if ps]
        raise ValueError(f"bayesian_network: cycle detected involving {unresolved!r}")

    # CPT must enumerate all parent assignments. Binary parents only for now.
    for n in nodes:
        if not n.parents:
            continue
        expected_keys = _enumerate_parent_assignments(n.parents)
        missing = expected_keys - set(n.cpt.keys())
        extra = set(n.cpt.keys()) - expected_keys
        if missing:
            raise ValueError(f"bayesian_network[{n.name}]: CPT missing keys {sorted(missing)!r}")
        if extra:
            raise ValueError(f"bayesian_network[{n.name}]: CPT has unexpected keys {sorted(extra)!r}")


def _enumerate_parent_assignments(parents: tuple[str, ...]) -> set[str]:
    """All ``p1=state1,p2=state2`` strings for binary parents."""
    states = ["present", "absent"]
    out: set[str] = set()
    for combo in product(states, repeat=len(parents)):
        out.add(",".join(f"{p}={s}" for p, s in zip(parents, combo, strict=True)))
    return out


def load_priors_override(path: Path | None = None) -> dict[str, float]:
    """Load operator-supplied prior overrides from ``priors.yaml`` in the
    config directory (RECON_CONFIG_DIR / legacy ~/.recon / XDG config).

    Returns an empty dict when the file does not exist or is malformed.
    Logs a warning on parse failure so the operator is not silently
    ignored. Never raises — bad override file should not crash inference.
    """
    if path is None:
        from recon_tool.paths import config_dir

        path = config_dir() / "priors.yaml"
    target = path
    if not target.exists():
        return {}
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("priors override at %s could not be read: %s", target, exc)
        return {}
    if not isinstance(raw, dict):
        logger.warning("priors override at %s: expected top-level mapping", target)
        return {}
    priors = raw.get("priors") if "priors" in raw else raw
    if not isinstance(priors, dict):
        logger.warning("priors override at %s: expected 'priors' mapping or top-level mapping", target)
        return {}
    out: dict[str, float] = {}
    for k, v in priors.items():
        if not isinstance(k, str):
            continue
        if not isinstance(v, int | float):
            continue
        fv = float(v)
        # Open interval (0, 1) to match the likelihood {0,1} ban: a root prior
        # pinned at 0 or 1 is a degeneracy operators rarely intend (one
        # mis-belief permanently pins the node). Operators wanting near-
        # certainty can use a near-bound value like 0.999.
        if not 0.0 < fv < 1.0:
            logger.warning("priors override at %s: value for %s outside (0, 1); ignored", target, k)
            continue
        out[k] = fv
    if out:
        logger.info("priors override applied to %d node(s) from %s", len(out), target)
    return out


def apply_priors_override(network: BayesianNetwork, override: dict[str, float]) -> BayesianNetwork:
    if not override:
        return network
    new_nodes: list[Node] = []
    for n in network.nodes:
        val = override.get(n.name)
        # Only root priors are overridable, and only within the open interval
        # (0, 1). The direct-argument path (infer(priors_override=...)) reaches
        # here without the file loader's range check, and a prior of 0/1 or an
        # out-of-range value would build a degenerate or invalid factor.
        if val is not None and not n.parents and 0.0 < val < 1.0:
            new_nodes.append(replace(n, prior=val))
        else:
            if val is not None and not n.parents:
                logger.warning("priors override for %s ignored: %s outside (0, 1)", n.name, val)
            new_nodes.append(n)
    return BayesianNetwork(version=network.version, nodes=tuple(new_nodes), calibration=network.calibration)
