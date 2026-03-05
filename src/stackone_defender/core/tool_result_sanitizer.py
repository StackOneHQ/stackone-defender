"""Tool Result Sanitizer.

Main integration layer that sanitizes complete tool results.
Handles structure traversal, risky field detection, and applies
appropriate sanitization based on risk level.
"""

from __future__ import annotations

import time
from typing import Any

from ..classifiers.pattern_detector import PatternDetector, create_pattern_detector
from ..classifiers.tier2_classifier import Tier2Classifier, create_tier2_classifier
from ..config import DEFAULT_CUMULATIVE_RISK_THRESHOLDS, DEFAULT_RISKY_FIELDS, DEFAULT_TOOL_RULES, DEFAULT_TRAVERSAL_CONFIG
from ..sanitizers.sanitizer import Sanitizer, create_sanitizer
from ..types import (
    CumulativeRiskTracker,
    DataBoundary,
    RiskLevel,
    RiskyFieldConfig,
    SanitizationContext,
    SanitizationMetadata,
    SanitizationResult,
    SizeMetrics,
    ToolSanitizationRule,
    TraversalConfig,
)
from ..utils.boundary import generate_data_boundary
from ..utils.field_detection import get_tool_rule, is_risky_field, should_skip_field
from ..utils.structure import (
    create_size_metrics,
    detect_structure_type,
    get_wrapped_data,
    is_paginated_response,
    should_continue_traversal,
    update_size_metrics,
)


class ToolResultSanitizer:
    """Sanitizes complete tool results."""

    def __init__(
        self,
        *,
        risky_fields: RiskyFieldConfig | None = None,
        traversal: TraversalConfig | None = None,
        tool_rules: list[ToolSanitizationRule] | None = None,
        default_risk_level: RiskLevel = "medium",
        use_tier1_classification: bool = True,
        use_tier2_classification: bool = False,
        tier2_config: dict | None = None,
        block_high_risk: bool = False,
        cumulative_risk_thresholds: dict[str, int] | None = None,
    ):
        self._risky_fields = risky_fields or DEFAULT_RISKY_FIELDS
        self._traversal = traversal or DEFAULT_TRAVERSAL_CONFIG
        self._tool_rules = tool_rules if tool_rules is not None else list(DEFAULT_TOOL_RULES)
        self._default_risk_level = default_risk_level
        self._use_tier1 = use_tier1_classification
        self._use_tier2 = use_tier2_classification
        self._block_high_risk = block_high_risk
        self._cumulative_thresholds = cumulative_risk_thresholds or dict(DEFAULT_CUMULATIVE_RISK_THRESHOLDS)

        self._sanitizer: Sanitizer = create_sanitizer()
        self._pattern_detector: PatternDetector = create_pattern_detector()
        self._tier2: Tier2Classifier | None = None
        if use_tier2_classification:
            self._tier2 = create_tier2_classifier(tier2_config)

    def warmup_tier2(self) -> None:
        if self._tier2:
            self._tier2.warmup()

    def is_tier2_ready(self) -> bool:
        return self._tier2.is_ready() if self._tier2 else False

    def sanitize(self, value: Any, *, tool_name: str, vertical: str | None = None, resource: str | None = None, risk_level: RiskLevel | None = None, boundary: DataBoundary | None = None) -> SanitizationResult:
        start_time = time.perf_counter()
        boundary = boundary or generate_data_boundary()
        tool_rule = get_tool_rule(tool_name, self._tool_rules)
        cumulative_risk = self._create_cumulative_tracker(tool_rule)
        size_metrics = create_size_metrics()

        context = SanitizationContext(
            path="",
            field_name="",
            tool_name=tool_name,
            vertical=vertical or self._extract_vertical(tool_name),
            resource=resource or self._extract_resource(tool_name),
            risk_level=risk_level or (tool_rule.sanitization_level if tool_rule and tool_rule.sanitization_level else self._default_risk_level),
            boundary=boundary,
            cumulative_risk=cumulative_risk,
        )

        metadata = SanitizationMetadata(
            overall_risk_level=context.risk_level,
            size_metrics=size_metrics,
        )

        sanitized = self._sanitize_value(value, context, tool_rule, metadata, 0)

        if self._should_escalate(cumulative_risk):
            metadata.cumulative_risk_escalated = True
            metadata.overall_risk_level = "high"

        metadata.total_latency_ms = (time.perf_counter() - start_time) * 1000
        metadata.size_metrics = size_metrics
        return SanitizationResult(sanitized=sanitized, metadata=metadata)

    # ------------------------------------------------------------------
    # Recursive traversal
    # ------------------------------------------------------------------

    def _sanitize_value(self, value: Any, context: SanitizationContext, tool_rule: ToolSanitizationRule | None, metadata: SanitizationMetadata, depth: int) -> Any:
        update_size_metrics(metadata.size_metrics, value)
        if not should_continue_traversal(metadata.size_metrics, depth, self._traversal.max_size, self._traversal.max_depth):
            return value
        if value is None:
            return value
        if isinstance(value, list):
            return self._sanitize_array(value, context, tool_rule, metadata, depth)
        if isinstance(value, dict):
            return self._sanitize_object(value, context, tool_rule, metadata, depth)
        return value

    def _sanitize_array(self, arr: list, context: SanitizationContext, tool_rule: ToolSanitizationRule | None, metadata: SanitizationMetadata, depth: int) -> list:
        metadata.size_metrics.array_count += 1

        if self._traversal.skip_large_arrays and len(arr) > self._traversal.large_array_threshold:
            sample_size = min(100, len(arr))
            sanitized = []
            for i in range(sample_size):
                ctx = SanitizationContext(
                    path=f"{context.path}[{i}]", field_name=context.field_name,
                    tool_name=context.tool_name, vertical=context.vertical,
                    resource=context.resource, risk_level=context.risk_level,
                    boundary=context.boundary, cumulative_risk=context.cumulative_risk,
                )
                sanitized.append(self._sanitize_value(arr[i], ctx, tool_rule, metadata, depth + 1))
            if len(arr) > sample_size:
                sanitized.append(f"[{len(arr) - sample_size} more items - sanitization skipped for performance]")
            return sanitized

        result = []
        for i, item in enumerate(arr):
            ctx = SanitizationContext(
                path=f"{context.path}[{i}]", field_name=context.field_name,
                tool_name=context.tool_name, vertical=context.vertical,
                resource=context.resource, risk_level=context.risk_level,
                boundary=context.boundary, cumulative_risk=context.cumulative_risk,
            )
            result.append(self._sanitize_value(item, ctx, tool_rule, metadata, depth + 1))
        return result

    def _sanitize_object(self, obj: dict, context: SanitizationContext, tool_rule: ToolSanitizationRule | None, metadata: SanitizationMetadata, depth: int) -> dict:
        metadata.size_metrics.object_count += 1

        if is_paginated_response(obj):
            return self._sanitize_paginated(obj, context, tool_rule, metadata, depth)

        if detect_structure_type(obj) == "wrapped":
            return self._sanitize_wrapped(obj, context, tool_rule, metadata, depth)

        result = {}
        for key, val in obj.items():
            field_path = f"{context.path}.{key}" if context.path else key
            field_ctx = SanitizationContext(
                path=field_path, field_name=key,
                tool_name=context.tool_name, vertical=context.vertical,
                resource=context.resource, risk_level=context.risk_level,
                boundary=context.boundary, cumulative_risk=context.cumulative_risk,
            )

            if should_skip_field(key, tool_rule):
                result[key] = val
                continue

            if self._is_field_risky(key, context.tool_name) and isinstance(val, str):
                result[key] = self._sanitize_string_field(val, field_ctx, tool_rule, metadata)
            else:
                result[key] = self._sanitize_value(val, field_ctx, tool_rule, metadata, depth + 1)
        return result

    def _sanitize_paginated(self, obj: dict, context: SanitizationContext, tool_rule: ToolSanitizationRule | None, metadata: SanitizationMetadata, depth: int) -> dict:
        result = dict(obj)
        for key in ("data", "results", "items", "records"):
            if key in obj and isinstance(obj[key], list):
                ctx = SanitizationContext(
                    path=f"{context.path}.{key}", field_name=context.field_name,
                    tool_name=context.tool_name, vertical=context.vertical,
                    resource=context.resource, risk_level=context.risk_level,
                    boundary=context.boundary, cumulative_risk=context.cumulative_risk,
                )
                result[key] = self._sanitize_array(obj[key], ctx, tool_rule, metadata, depth + 1)
                break
        return result

    def _sanitize_wrapped(self, obj: dict, context: SanitizationContext, tool_rule: ToolSanitizationRule | None, metadata: SanitizationMetadata, depth: int) -> dict:
        result = {}
        for key, val in obj.items():
            field_path = f"{context.path}.{key}" if context.path else key
            field_ctx = SanitizationContext(
                path=field_path, field_name=key,
                tool_name=context.tool_name, vertical=context.vertical,
                resource=context.resource, risk_level=context.risk_level,
                boundary=context.boundary, cumulative_risk=context.cumulative_risk,
            )
            wrapped = get_wrapped_data({key: val})
            if wrapped is not None:
                result[key] = self._sanitize_array(val, field_ctx, tool_rule, metadata, depth + 1)
            else:
                result[key] = self._sanitize_value(val, field_ctx, tool_rule, metadata, depth + 1)
        return result

    # ------------------------------------------------------------------
    # String field sanitization
    # ------------------------------------------------------------------

    def _sanitize_string_field(self, value: str, context: SanitizationContext, _tool_rule: ToolSanitizationRule | None, metadata: SanitizationMetadata) -> str:
        metadata.size_metrics.string_count += 1
        risk_level = context.risk_level
        tier1_patterns: list[str] = []

        if self._use_tier1:
            result = self._pattern_detector.analyze(value)
            if result.has_detections:
                tier1_patterns = [m.pattern for m in result.matches]
                if result.suggested_risk == "critical":
                    risk_level = "critical"
                elif result.suggested_risk == "high" and risk_level != "critical":
                    risk_level = "high"
                elif result.suggested_risk == "medium" and risk_level == "low":
                    risk_level = "medium"
                if context.cumulative_risk:
                    self._update_cumulative_risk(context.cumulative_risk, risk_level, tier1_patterns)

        if self._block_high_risk and risk_level in ("high", "critical"):
            metadata.fields_sanitized.append(context.path)
            metadata.methods_by_field[context.path] = ["pattern_removal"] if tier1_patterns else []
            if tier1_patterns:
                metadata.patterns_removed_by_field[context.path] = tier1_patterns
            return "[CONTENT BLOCKED FOR SECURITY]"

        san_result = self._sanitizer.sanitize(value, risk_level=risk_level, boundary=context.boundary, field_name=context.field_name)

        if san_result.methods_applied:
            metadata.fields_sanitized.append(context.path)
            metadata.methods_by_field[context.path] = san_result.methods_applied
            if san_result.patterns_removed:
                metadata.patterns_removed_by_field[context.path] = san_result.patterns_removed

        return san_result.sanitized

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_field_risky(self, field_name: str, tool_name: str) -> bool:
        return is_risky_field(field_name, self._risky_fields, tool_name)

    def _create_cumulative_tracker(self, tool_rule: ToolSanitizationRule | None) -> CumulativeRiskTracker:
        thresholds = (tool_rule.cumulative_risk_thresholds if tool_rule and tool_rule.cumulative_risk_thresholds else self._cumulative_thresholds)
        return CumulativeRiskTracker(escalation_threshold=dict(thresholds))

    @staticmethod
    def _update_cumulative_risk(tracker: CumulativeRiskTracker, risk_level: RiskLevel, patterns: list[str]) -> None:
        tracker.total_fields_processed += 1
        if risk_level in ("high", "critical"):
            tracker.high_risk_count += 1
        elif risk_level == "medium":
            tracker.medium_risk_count += 1
        if patterns:
            tracker.suspicious_patterns.extend(patterns)

    @staticmethod
    def _should_escalate(tracker: CumulativeRiskTracker) -> bool:
        if tracker.high_risk_count >= tracker.escalation_threshold["high"]:
            return True
        if tracker.medium_risk_count >= tracker.escalation_threshold["medium"]:
            return True
        if len(tracker.suspicious_patterns) >= tracker.escalation_threshold["patterns"]:
            return True
        return False

    @staticmethod
    def _extract_vertical(tool_name: str) -> str:
        parts = tool_name.split("_")
        if len(parts) >= 2:
            return parts[1] if parts[0] == "unified" else parts[0]
        return "unknown"

    @staticmethod
    def _extract_resource(tool_name: str) -> str:
        parts = tool_name.split("_")
        if len(parts) >= 3:
            return parts[-1]
        return "unknown"


def create_tool_result_sanitizer(**kwargs) -> ToolResultSanitizer:
    return ToolResultSanitizer(**kwargs)
