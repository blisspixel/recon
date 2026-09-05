"""Validate configurable regular expressions before compilation."""

from __future__ import annotations

import logging
import re
from functools import lru_cache

logger = logging.getLogger("recon")

# Hard cap on pattern length. This is not sufficient by itself; structural
# checks below reject the backtracking shapes accepted by Python's regex engine.
_MAX_PATTERN_LENGTH = 500

# Keep compiled catalog expressions outside ``re``'s implementation-private
# cache. The shipped catalog plus the bounded ephemeral allowance fit within
# this ceiling, while custom catalogs cannot grow the long-lived MCP process
# without limit. Each retained key is also bounded by ``_MAX_PATTERN_LENGTH``.
_MAX_COMPILED_REGEX_CACHE_SIZE = 2048


@lru_cache(maxsize=_MAX_COMPILED_REGEX_CACHE_SIZE)
def _compile_regex_cached(pattern: str, flags: int) -> re.Pattern[str]:
    """Compile one bounded expression for immutable cross-call reuse."""
    return re.compile(pattern, flags)


def compile_regex(pattern: str, flags: int | re.RegexFlag = 0) -> re.Pattern[str] | None:
    """Return a cached compiled expression, or ``None`` for invalid input.

    Structural ReDoS admission remains the responsibility of
    :func:`validate_regex`. Matchers use this helper defensively because their
    public or test-facing pattern collections can still contain malformed
    objects. Oversized values are rejected before they can become cache keys.
    """
    if not pattern or len(pattern) > _MAX_PATTERN_LENGTH:
        return None
    try:
        return _compile_regex_cached(pattern, int(flags))
    except (OverflowError, ValueError, re.error):
        return None


def clear_compiled_regex_cache() -> None:
    """Drop every compiled expression after a catalog generation changes."""
    _compile_regex_cached.cache_clear()


_REDOS_RE = re.compile(
    r"\([^)]*[+*][^)]*\)[+*{]"  # (group-with-quantifier) then +, *, or {n}
    r"|"
    r"(?:[+*]\??\.\*[+*])"  # quantifier + .* + quantifier
    r"|"
    r"(?:\.[+*]\??\.[+*]\??\.[+*])"  # three adjacent quantified atoms
)

_LITERAL_BRANCH_RE = re.compile(r"(?:[a-zA-Z0-9_/-]|\\[.\^$*+?{}\[\]\\()|/-])+")


def _disjoint_literal_branches(body: str) -> bool:
    """Prove a repeated alternation is a prefix-free set of ASCII literals.

    Anything requiring regex interpretation, including nested groups, encoded
    characters, empty branches, or assertions, fails closed. Merely comparing
    regex source text misses equivalent ways to match the same characters.
    """
    body = re.sub(r"^\?[aimsxLu-]*:", "", body)
    branches = re.split(r"(?<!\\)\|", body)
    if any(_LITERAL_BRANCH_RE.fullmatch(branch) is None for branch in branches):
        return False
    literals = [re.sub(r"\\(.)", r"\1", branch).casefold() for branch in branches]
    return all(
        not first.startswith(second) and not second.startswith(first)
        for index, first in enumerate(literals)
        for second in literals[index + 1 :]
    )


def _alternation_redos(pattern: str) -> bool:
    """Check every repeated group, including alternations in child groups."""
    stack: list[tuple[int, bool]] = []
    # Replace escaped atoms and classes with equal-width placeholders so the
    # scan keeps source offsets without treating their punctuation as syntax.
    structural = _strip_escapes_and_classes(pattern, preserve_width=True)
    for index, char in enumerate(structural):
        if char == "(":
            stack.append((index, False))
        elif char == "|" and stack:
            opening, _ = stack[-1]
            stack[-1] = (opening, True)
        elif char == ")" and stack:
            opening, has_alternation = stack.pop()
            if has_alternation and stack:
                parent, _ = stack[-1]
                stack[-1] = (parent, True)
            following = structural[index + 1 : index + 2]
            if (
                has_alternation
                and following
                and following in "+*{"
                and not _disjoint_literal_branches(pattern[opening + 1 : index])
            ):
                return True
    return False


def _strip_escapes_and_classes(pattern: str, *, preserve_width: bool = False) -> str:
    """Remove escaped characters and character classes for structural scans."""
    output: list[str] = []
    index, length = 0, len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            if preserve_width:
                output.append("_" * min(2, length - index))
            index += 2
            continue
        if char == "[":
            opening = index
            index += 1
            if index < length and pattern[index] == "^":
                index += 1
            if index < length and pattern[index] == "]":
                index += 1
            while index < length and pattern[index] != "]":
                index += 2 if pattern[index] == "\\" else 1
            index += 1
            if preserve_width:
                output.append("_" * (index - opening))
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _is_quantifier_at(cleaned: str, index: int) -> bool:
    """Whether the character at ``index`` repeats the atom before it.

    ``?`` carries three meanings and only one of them repeats: it makes the
    preceding atom optional in ``a?``, but it opens a group construct in
    ``(?:`` and ``(?=``, and it makes a preceding quantifier lazy in ``a+?``.
    Distinguishing them is what lets the nested-quantifier scan below count
    ``?`` at all without rejecting every non-capturing group.
    """
    char = cleaned[index]
    if char in "*+{":
        return True
    if char != "?":
        return False
    previous = cleaned[index - 1] if index else ""
    return previous not in {"(", "*", "+", "?", "}"}


def _has_nested_quantifier(pattern: str) -> bool:
    """Return whether a quantified group contains another quantifier.

    ``?`` counts as an inner quantifier. Omitting it admitted ``(a?){50}a{50}$``,
    which backtracks catastrophically: 49 subject characters were enough to run
    past a minute, far below the pattern-length cap that was assumed to bound
    whatever this heuristic misses.
    """
    cleaned = _strip_escapes_and_classes(pattern)
    stack: list[int] = []
    for index, char in enumerate(cleaned):
        if char == "(":
            stack.append(index)
        elif char == ")" and stack:
            opening = stack.pop()
            following = cleaned[index + 1] if index + 1 < len(cleaned) else ""
            if (
                following
                and following in "+*{"
                and any(_is_quantifier_at(cleaned, inner) for inner in range(opening + 1, index))
            ):
                return True
    return False


def _repetition_operator_count(pattern: str) -> int:
    """Count repetition operators outside escapes and character classes."""
    cleaned = _strip_escapes_and_classes(pattern)
    return sum(1 for index in range(len(cleaned)) if _is_quantifier_at(cleaned, index))


def validate_regex(pattern: str, source: str) -> bool:
    """Return whether a pattern compiles and meets the accepted complexity bounds.

    The validation rejects empty and oversized patterns, recognized ambiguous
    backtracking structures, and invalid syntax. Process-injected expressions
    use a stricter deterministic subset with at most one repetition operator.
    """
    if not pattern:
        logger.warning("Empty regex pattern in %s - skipped", source)
        return False
    if len(pattern) > _MAX_PATTERN_LENGTH:
        logger.warning(
            "Regex pattern too long (%d chars) in %s - skipped",
            len(pattern),
            source,
        )
        return False
    if _REDOS_RE.search(pattern) or _alternation_redos(pattern) or _has_nested_quantifier(pattern):
        logger.warning(
            "Potentially unsafe regex (catastrophic backtracking) %r in %s - skipped",
            pattern,
            source,
        )
        return False
    if source.startswith("ephemeral:") and _repetition_operator_count(pattern) > 1:
        logger.warning(
            "Ephemeral regex contains multiple repetition operators %r in %s - skipped",
            pattern,
            source,
        )
        return False
    try:
        _compile_regex_cached(pattern, 0)
    except (OverflowError, re.error) as exc:
        logger.warning("Invalid regex %r in %s: %s - skipped", pattern, source, exc)
        return False
    return True
