"""Utility functions for prompt defense."""

from .boundary import generate_data_boundary, generate_xml_boundary, wrap_with_boundary
from .field_detection import get_tool_override_fields, get_tool_rule, is_risky_field, matches_wildcard, should_skip_field
from .structure import (
    create_size_metrics,
    detect_structure_type,
    estimate_size,
    get_wrapped_data,
    is_paginated_response,
    is_plain_object,
    should_continue_traversal,
    update_size_metrics,
)

__all__ = [
    "create_size_metrics",
    "detect_structure_type",
    "estimate_size",
    "generate_data_boundary",
    "generate_xml_boundary",
    "get_tool_override_fields",
    "get_tool_rule",
    "get_wrapped_data",
    "is_paginated_response",
    "is_plain_object",
    "is_risky_field",
    "matches_wildcard",
    "should_continue_traversal",
    "should_skip_field",
    "update_size_metrics",
    "wrap_with_boundary",
]
