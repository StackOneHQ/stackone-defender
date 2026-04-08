"""Field detection utilities for identifying risky fields."""

from __future__ import annotations

import re

from ..types import RiskyFieldConfig


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


def get_tool_override_fields(tool_name: str, overrides: dict[str, list[str]]) -> list[str] | None:
    """Return override fields for *tool_name*, or None if no override matches."""
    return _get_tool_override_fields(tool_name, overrides)


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
