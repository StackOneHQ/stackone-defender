"""Field detection utilities for identifying risky fields."""

from __future__ import annotations

import re

from ..types import RiskyFieldConfig, ToolSanitizationRule


def is_risky_field(field_name: str, config: RiskyFieldConfig, tool_name: str | None = None) -> bool:
    if tool_name and config.tool_overrides:
        override_fields = _get_tool_override_fields(tool_name, config.tool_overrides)
        if override_fields is not None:
            return field_name in override_fields

    if field_name in config.field_names:
        return True

    for pattern in config.field_patterns:
        if pattern.search(field_name):
            return True

    return False


def _get_tool_override_fields(tool_name: str, overrides: dict[str, list[str]]) -> list[str] | None:
    if tool_name in overrides:
        return overrides[tool_name]
    for pattern, fields in overrides.items():
        if matches_wildcard(tool_name, pattern):
            return fields
    return None


def matches_wildcard(tool_name: str, pattern: str) -> bool:
    regex_pattern = re.escape(pattern).replace(r"\*", ".*")
    return bool(re.match(f"^{regex_pattern}$", tool_name))


def get_tool_rule(tool_name: str, rules: list[ToolSanitizationRule]) -> ToolSanitizationRule | None:
    for rule in rules:
        if isinstance(rule.tool_pattern, str):
            if tool_name == rule.tool_pattern or matches_wildcard(tool_name, rule.tool_pattern):
                return rule
        elif isinstance(rule.tool_pattern, re.Pattern):
            if rule.tool_pattern.search(tool_name):
                return rule
    return None


def should_skip_field(field_name: str, rule: ToolSanitizationRule | None = None) -> bool:
    if not rule or not rule.skip_fields:
        return False
    return field_name in rule.skip_fields


def get_max_field_length(field_name: str, rule: ToolSanitizationRule | None = None, default_max: int = 50000) -> int:
    if rule and rule.max_field_lengths and field_name in rule.max_field_lengths:
        return rule.max_field_lengths[field_name]
    return default_max
