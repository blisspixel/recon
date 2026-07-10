"""Validate configurable regular expressions before compilation."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger("recon")

# Hard cap on pattern length. This is not sufficient by itself; structural
# checks below reject the backtracking shapes accepted by Python's regex engine.
_MAX_PATTERN_LENGTH = 500

_REDOS_RE = re.compile(
    r"\([^)]*[+*][^)]*\)[+*{]"  # (group-with-quantifier) then +, *, or {n}
    r"|"
    r"(?:[+*]\??\.\*[+*])"  # quantifier + .* + quantifier
    r"|"
    r"(?:\.[+*]\??\.[+*]\??\.[+*])"  # three adjacent quantified atoms
)

# Only prefix-overlapping alternatives are rejected. Disjoint alternatives such
# as (foo|bar)+ remain useful and do not have the same ambiguous partitioning.
_ALT_GROUP_QUANT_RE = re.compile(r"\(([^()]*\|[^()]*)\)[+*{]")


def _alternation_redos(pattern: str) -> bool:
    """Return whether a simple quantified alternation has prefix overlap."""
    pattern = re.sub(r"\(\?[aimsxLu]*:", "(", pattern)
    for match in _ALT_GROUP_QUANT_RE.finditer(pattern):
        branches = [branch.strip() for branch in match.group(1).split("|")]
        for index, first in enumerate(branches):
            for second in branches[index + 1 :]:
                if first and second and (first.startswith(second) or second.startswith(first)):
                    return True
    return False


def _strip_escapes_and_classes(pattern: str) -> str:
    """Remove escaped characters and character classes for structural scans."""
    output: list[str] = []
    index, length = 0, len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            index += 1
            if index < length and pattern[index] == "^":
                index += 1
            if index < length and pattern[index] == "]":
                index += 1
            while index < length and pattern[index] != "]":
                index += 2 if pattern[index] == "\\" else 1
            index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _has_nested_quantifier(pattern: str) -> bool:
    """Return whether a quantified group contains another quantifier."""
    cleaned = _strip_escapes_and_classes(pattern)
    stack: list[int] = []
    for index, char in enumerate(cleaned):
        if char == "(":
            stack.append(index)
        elif char == ")" and stack:
            opening = stack.pop()
            following = cleaned[index + 1] if index + 1 < len(cleaned) else ""
            if following in "+*{" and any(mark in cleaned[opening + 1 : index] for mark in "+*{"):
                return True
    return False


def _repetition_operator_count(pattern: str) -> int:
    """Count repetition operators outside escapes and character classes."""
    cleaned = _strip_escapes_and_classes(pattern)
    count = 0
    for index, char in enumerate(cleaned):
        if char in "*+{":
            count += 1
        elif char == "?":
            previous = cleaned[index - 1] if index else ""
            if previous not in {"(", "*", "+", "?", "}"}:
                count += 1
    return count


def validate_regex(pattern: str, source: str) -> bool:
    """Return whether a pattern compiles and meets the accepted complexity bounds.

    The validation rejects empty and oversized patterns, recognized ambiguous
    backtracking structures, and invalid syntax. Session-injected expressions
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
        re.compile(pattern)
    except (OverflowError, re.error) as exc:
        logger.warning("Invalid regex %r in %s: %s - skipped", pattern, source, exc)
        return False
    return True
