"""Binary rubric scoring for agentic UX validation transcripts.

The roadmap (v1.9.2) defines five binary checks. Three are per-session
(read posterior block, cite credible interval explicitly, mention
``--explain-dag`` / ``explain_dag``); two are cross-session diffs
(``sparse=true`` changed the conclusion vs the dense run, ``--fusion``
on vs off changed the conclusion).

Implementations are intentionally simple regex/keyword scans. Smarter
NLP would be more accurate but less reproducible, and the rubric is
about *whether the affordances were used at all*, not about how
eloquently. A keyword scan catches that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --- Per-session checks ------------------------------------------------------

_POSTERIOR_PATTERNS = [
    re.compile(r"\bposterior(s|_observations|\s+observation)?\b", re.IGNORECASE),
    re.compile(r"\bn[_\s]?eff\b", re.IGNORECASE),
    re.compile(r"\bevidence_used\b", re.IGNORECASE),
    re.compile(r"\bsparse\s*=\s*true\b", re.IGNORECASE),
]

_INTERVAL_PATTERNS = [
    re.compile(r"\bcredible\s+interval\b", re.IGNORECASE),
    re.compile(r"\binterval[_\s]?(low|high)\b", re.IGNORECASE),
    # Numeric range like "0.21 to 0.95", "[0.21, 0.95]", "0.21–0.95"
    re.compile(r"\b0\.\d+\s*(?:to|[-–—,]\s*0\.|\]\s*to\s*\[?\s*0\.|\.\.\s*0\.)\s*\d", re.IGNORECASE),
]

_EXPLAIN_DAG_PATTERNS = [
    re.compile(r"--?explain[-_]dag\b", re.IGNORECASE),
    re.compile(r"\bexplain_dag\b", re.IGNORECASE),
    re.compile(r"\bevidence\s+DAG\b", re.IGNORECASE),
]

# Confidence-modulating language used to detect "did sparse change the
# conclusion?" — the assumption is that an agent that read sparse=true
# (or the wide intervals) will reach for hedge words it would not use
# on a dense fixture.
_HEDGE_PATTERNS = [
    re.compile(
        r"\b(?:low|limited|insufficient|sparse|thin|weak)\s+(?:evidence|confidence|signal|data)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bnot\s+enough\b", re.IGNORECASE),
    re.compile(r"\bunder-?attribut", re.IGNORECASE),
    re.compile(r"\bcannot\s+(?:confirm|conclude|determine)\b", re.IGNORECASE),
    re.compile(r"\bhardened\b", re.IGNORECASE),
    re.compile(r"\bobscur", re.IGNORECASE),
]

_PASSIVE_CEILING_PATTERN = re.compile(
    r"\b(sparse|passive\s+ceiling|hardened|insufficient)\b",
    re.IGNORECASE,
)


def _matches_any(text: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(p.search(text) for p in patterns)


def _hedge_count(text: str) -> int:
    return sum(1 for p in _HEDGE_PATTERNS if p.search(text))


@dataclass(frozen=True)
class SessionScore:
    """Per-session binary checks."""

    persona: str
    fixture: str
    fusion: bool
    read_posterior_block: bool
    cited_credible_interval: bool
    mentioned_explain_dag: bool
    hedge_count: int


def score_session(persona: str, fixture: str, fusion: bool, transcript_text: str) -> SessionScore:
    """Score a single agent transcript against the per-session rubric."""
    return SessionScore(
        persona=persona,
        fixture=fixture,
        fusion=fusion,
        read_posterior_block=_matches_any(transcript_text, _POSTERIOR_PATTERNS),
        cited_credible_interval=_matches_any(transcript_text, _INTERVAL_PATTERNS),
        mentioned_explain_dag=_matches_any(transcript_text, _EXPLAIN_DAG_PATTERNS),
        hedge_count=_hedge_count(transcript_text),
    )


# --- Cross-session diffs -----------------------------------------------------


@dataclass(frozen=True)
class DiffScore:
    """Comparison between two related sessions."""

    persona: str
    label: str
    differed: bool
    reason: str


def diff_sparse_vs_dense(
    dense: SessionScore,
    sparse: SessionScore,
    *,
    dense_text: str,
    sparse_text: str,
) -> DiffScore:
    """Did ``sparse=true`` change the agent's conclusion vs the dense run?

    Heuristic: TRUE if the sparse transcript uses strictly more hedge
    phrases than the dense transcript, OR if the sparse transcript
    contains an explicit "sparse" / "passive ceiling" / "hardened"
    acknowledgment that the dense one does not. Both signals together
    strengthen the verdict; either alone is enough to mark the diff
    positive — the rubric only asks whether the conclusion changed,
    not how dramatically.
    """
    if dense.persona != sparse.persona:
        raise ValueError("diff_sparse_vs_dense expects matching personas")
    hedge_grew = sparse.hedge_count > dense.hedge_count
    sparse_acknowledged = bool(_PASSIVE_CEILING_PATTERN.search(sparse_text))
    dense_did_not = not _PASSIVE_CEILING_PATTERN.search(dense_text)
    differed = hedge_grew or (sparse_acknowledged and dense_did_not)
    if differed:
        reason = (
            f"sparse hedge count {sparse.hedge_count} > dense {dense.hedge_count}"
            if hedge_grew
            else "sparse acknowledged passive ceiling; dense did not"
        )
    else:
        reason = "no observable change in hedge language between dense and sparse"
    return DiffScore(persona=dense.persona, label="sparse_vs_dense", differed=differed, reason=reason)


def diff_fusion_on_vs_off(
    on_score: SessionScore,
    off_score: SessionScore,
    *,
    on_text: str,
    off_text: str,
) -> DiffScore:
    """Did ``--fusion`` on vs off change the agent's conclusion?

    Heuristic: TRUE if the fusion-on transcript referenced posterior
    or credible-interval material the fusion-off transcript did not.
    Reading the posterior block at all (when it exists) is the
    primary signal; numeric interval citation is a stronger one.
    """
    if on_score.persona != off_score.persona or on_score.fixture != off_score.fixture:
        raise ValueError("diff_fusion_on_vs_off expects matching persona and fixture")
    differed = (on_score.read_posterior_block and not off_score.read_posterior_block) or (
        on_score.cited_credible_interval and not off_score.cited_credible_interval
    )
    if differed:
        reason = "fusion-on cited posterior material absent from fusion-off"
    elif not on_score.read_posterior_block:
        reason = "fusion-on transcript did not engage with the posterior block at all"
    else:
        reason = (
            "both transcripts cited posterior material — fusion presence did not change "
            "conclusion in a way the rubric can detect"
        )
    # Bonus signal: fusion-off should not invent posterior numbers
    invented = (not on_score.read_posterior_block and off_score.read_posterior_block) and bool(
        re.search(r"0\.\d{2,}", off_text),
    )
    if invented:
        reason += " (fusion-off transcript invents numeric posteriors, which would be a hallucination signal)"
    # Touch on_text so the parameter is intentionally consumed by the diff routine.
    if on_text and not on_text.strip():  # pragma: no cover - defensive guard
        reason += " (note: fusion-on transcript was blank)"
    return DiffScore(persona=on_score.persona, label="fusion_on_vs_off", differed=differed, reason=reason)


# --- Aggregate ---------------------------------------------------------------


@dataclass(frozen=True)
class RubricSummary:
    """Aggregate rubric outcome across all sessions."""

    sessions: list[SessionScore]
    diffs: list[DiffScore]

    @property
    def session_table(self) -> list[dict[str, object]]:
        return [
            {
                "persona": s.persona,
                "fixture": s.fixture,
                "fusion": s.fusion,
                "read_posterior_block": s.read_posterior_block,
                "cited_credible_interval": s.cited_credible_interval,
                "mentioned_explain_dag": s.mentioned_explain_dag,
                "hedge_count": s.hedge_count,
            }
            for s in self.sessions
        ]

    @property
    def diff_table(self) -> list[dict[str, object]]:
        return [
            {
                "persona": d.persona,
                "label": d.label,
                "differed": d.differed,
                "reason": d.reason,
            }
            for d in self.diffs
        ]
