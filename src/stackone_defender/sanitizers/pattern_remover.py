"""Pattern Removal / Redaction.

Removes or redacts known injection patterns from text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..classifiers.patterns import (
    ALL_PATTERNS,
    COMMAND_EXECUTION_PATTERNS,
    INSTRUCTION_OVERRIDE_PATTERNS,
    ROLE_ASSUMPTION_PATTERNS,
    SECURITY_BYPASS_PATTERNS,
)
from ..types import PatternDefinition


@dataclass
class PatternRemovalResult:
    text: str
    patterns_removed: list[str] = field(default_factory=list)
    replacement_count: int = 0


def remove_patterns(
    text: str,
    *,
    replacement: str = "[REDACTED]",
    preserve_length: bool = False,
    preserve_char: str = "\u2588",
    high_severity_only: bool = False,
    categories: list[str] | None = None,
    custom_patterns: list[re.Pattern] | None = None,
) -> PatternRemovalResult:
    if not text:
        return PatternRemovalResult(text=text)

    patterns = _get_patterns(high_severity_only, categories)
    result = text
    patterns_removed: list[str] = []
    replacement_count = 0

    for defn in patterns:
        if defn.pattern.search(result):
            def _replace(m: re.Match, _defn: PatternDefinition = defn) -> str:
                nonlocal replacement_count
                replacement_count += 1
                if _defn.id not in patterns_removed:
                    patterns_removed.append(_defn.id)
                return preserve_char * len(m.group(0)) if preserve_length else replacement
            result = defn.pattern.sub(_replace, result)

    if custom_patterns:
        for cp in custom_patterns:
            if cp.search(result):
                def _custom_replace(m: re.Match) -> str:
                    nonlocal replacement_count
                    replacement_count += 1
                    if "custom" not in patterns_removed:
                        patterns_removed.append("custom")
                    return preserve_char * len(m.group(0)) if preserve_length else replacement
                result = cp.sub(_custom_replace, result)

    return PatternRemovalResult(text=result, patterns_removed=patterns_removed, replacement_count=replacement_count)


def _get_patterns(high_severity_only: bool, categories: list[str] | None) -> list[PatternDefinition]:
    patterns = list(ALL_PATTERNS)
    if high_severity_only:
        patterns = [p for p in patterns if p.severity == "high"]
    if categories:
        patterns = [p for p in patterns if p.category in categories]
    return patterns


def remove_instruction_overrides(text: str, replacement: str = "[REDACTED]") -> PatternRemovalResult:
    return _remove_category(text, INSTRUCTION_OVERRIDE_PATTERNS, replacement)


def remove_role_assumptions(text: str, replacement: str = "[REDACTED]") -> PatternRemovalResult:
    return _remove_category(text, ROLE_ASSUMPTION_PATTERNS, replacement)


def remove_security_bypasses(text: str, replacement: str = "[REDACTED]") -> PatternRemovalResult:
    return _remove_category(text, SECURITY_BYPASS_PATTERNS, replacement)


def remove_command_executions(text: str, replacement: str = "[REDACTED]") -> PatternRemovalResult:
    return _remove_category(text, COMMAND_EXECUTION_PATTERNS, replacement)


def _remove_category(text: str, patterns: list[PatternDefinition], replacement: str) -> PatternRemovalResult:
    if not text:
        return PatternRemovalResult(text=text)

    result = text
    patterns_removed: list[str] = []
    replacement_count = 0

    for defn in patterns:
        if defn.pattern.search(result):
            def _replace(m: re.Match, _defn: PatternDefinition = defn) -> str:
                nonlocal replacement_count
                replacement_count += 1
                if _defn.id not in patterns_removed:
                    patterns_removed.append(_defn.id)
                return replacement
            result = defn.pattern.sub(_replace, result)

    return PatternRemovalResult(text=result, patterns_removed=patterns_removed, replacement_count=replacement_count)
