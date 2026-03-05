"""Structure detection and handling utilities."""

from __future__ import annotations

from ..types import SizeMetrics, StructureType


def detect_structure_type(value: object) -> StructureType:
    if value is None:
        return "null"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        keys = set(value.keys())
        if keys & {"data", "results", "items", "records"}:
            return "wrapped"
        return "object"
    return "primitive"


def is_paginated_response(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    keys = set(value.keys())
    has_data = bool(keys & {"data", "results", "items", "records"})
    has_pagination = bool(
        keys & {"next", "previous", "nextPage", "prevPage", "pagination", "page", "total", "totalCount", "hasMore", "cursor"}
    )
    return has_data and has_pagination


def get_wrapped_data(value: dict) -> list | None:
    for key in ("data", "results", "items", "records"):
        if key in value and isinstance(value[key], list):
            return value[key]
    return None


def create_size_metrics() -> SizeMetrics:
    return SizeMetrics()


def estimate_size(value: object) -> int:
    if value is None:
        return 4
    if isinstance(value, str):
        return len(value) + 2
    if isinstance(value, (int, float)):
        return len(str(value))
    if isinstance(value, bool):
        return 4 if value else 5
    if isinstance(value, list):
        return 2 + max(0, len(value) - 1)
    if isinstance(value, dict):
        key_overhead = sum(len(k) + 3 for k in value.keys())
        comma_overhead = max(0, len(value) - 1)
        return 2 + key_overhead + comma_overhead
    return 0


def update_size_metrics(metrics: SizeMetrics, value: object) -> None:
    metrics.estimated_bytes += estimate_size(value)
    if isinstance(value, str):
        metrics.string_count += 1
    elif isinstance(value, list):
        metrics.array_count += 1
    elif isinstance(value, dict):
        metrics.object_count += 1


def is_plain_object(value: object) -> bool:
    """Check if *value* is a plain dict (not list, None, or primitive)."""
    return isinstance(value, dict)


def should_continue_traversal(metrics: SizeMetrics, current_depth: int, max_size: int, max_depth: int) -> bool:
    if current_depth > max_depth:
        metrics.depth_limit_hit = True
        return False
    if metrics.estimated_bytes > max_size:
        metrics.size_limit_hit = True
        return False
    return True
