"""PromptDefense - Main Entry Point.

The primary class for using the prompt defense framework.
Provides a simple API for defending tool results against prompt injection.
"""

from __future__ import annotations

import time
from typing import Any

from ..classifiers.pattern_detector import PatternDetector, create_pattern_detector
from ..classifiers.tier2_classifier import Tier2Classifier, create_tier2_classifier
from ..config import create_config
from ..types import DefenseResult, PromptDefenseConfig, RiskLevel, Tier1Result
from .tool_result_sanitizer import ToolResultSanitizer, create_tool_result_sanitizer


def _extract_strings(obj: Any, fields: list[str] | None = None) -> list[str]:
    """Recursively extract string values from an object for Tier 2.

    If ``fields`` is None or empty, all strings are collected. Otherwise only
    strings under matching dict keys are collected (via full-depth ``collect_all``);
    non-matching keys are traversed recursively without collecting string leaves
    under them (matches post-ENG-12518 TypeScript behavior).
    """
    strings: list[str] = []

    def collect_all(value: Any) -> None:
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, list):
            for item in value:
                collect_all(item)
        elif isinstance(value, dict):
            for v in value.values():
                collect_all(v)

    if fields is None or len(fields) == 0:
        collect_all(obj)
        return strings

    field_set = set(fields)

    def traverse(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                traverse(item)
        elif isinstance(value, dict):
            for k, v in value.items():
                if k in field_set:
                    collect_all(v)
                else:
                    traverse(v)

    traverse(obj)
    return strings


_RISK_LEVELS: list[RiskLevel] = ["low", "medium", "high", "critical"]


class PromptDefense:
    """Main API for prompt injection defense."""

    def __init__(
        self,
        *,
        config: dict | None = None,
        enable_tier1: bool = True,
        enable_tier2: bool = True,
        tier2_config: dict | None = None,
        tier2_fields: list[str] | None = None,
        block_high_risk: bool = False,
        default_risk_level: RiskLevel = "medium",
        use_default_tool_rules: bool = False,
    ):
        self._config: PromptDefenseConfig = create_config(config)
        if block_high_risk:
            self._config.block_high_risk = True

        self._tier2_fields = tier2_fields

        tool_rules = (config or {}).get("tool_rules") or (self._config.tool_rules if use_default_tool_rules else [])

        self._tool_sanitizer: ToolResultSanitizer = create_tool_result_sanitizer(
            risky_fields=self._config.risky_fields,
            traversal=self._config.traversal,
            tool_rules=tool_rules,
            default_risk_level=default_risk_level,
            use_tier1_classification=enable_tier1,
            block_high_risk=block_high_risk,
            cumulative_risk_thresholds=self._config.cumulative_risk_thresholds,
        )

        self._pattern_detector: PatternDetector = create_pattern_detector()
        self._tier2: Tier2Classifier | None = None

        if enable_tier2:
            self._tier2 = create_tier2_classifier(tier2_config)

    def warmup_tier2(self) -> None:
        if self._tier2:
            self._tier2.warmup()

    def is_tier2_ready(self) -> bool:
        return self._tier2.is_ready() if self._tier2 else False

    def defend_tool_result(self, value: Any, tool_name: str) -> DefenseResult:
        """Defend a tool result using Tier 1 and optionally Tier 2 classification."""
        start_time = time.perf_counter()

        # Tier 1: pattern-based sanitization
        sanitized = self._tool_sanitizer.sanitize(value, tool_name=tool_name)

        # Collect Tier 1 metadata
        prm = sanitized.metadata.patterns_removed_by_field
        mbf = sanitized.metadata.methods_by_field
        detections = list(dict.fromkeys(p for patterns in prm.values() for p in patterns))

        active_methods = {"role_stripping", "pattern_removal", "encoding_detection"}
        fields_sanitized = [
            field for field, methods in mbf.items()
            if any(m in active_methods for m in methods)
        ]

        # Tier 2: ML classification on raw value
        tier2_score: float | None = None
        max_sentence: str | None = None
        tier2_risk: RiskLevel = "low"
        tier2_skip_reason: str | None = None

        if self._tier2:
            opts_explicit = self._tier2_fields if self._tier2_fields is not None else self._config.tier2.tier2_fields
            if opts_explicit is not None:
                fields_for_tier2 = None if len(opts_explicit) == 0 else opts_explicit
            elif sanitized.metadata.risky_field_names:
                fields_for_tier2 = sanitized.metadata.risky_field_names
            else:
                fields_for_tier2 = None

            strings = _extract_strings(value, fields_for_tier2)
            combined = "\n\n".join(strings)
            if not combined:
                if opts_explicit is not None and len(opts_explicit) > 0:
                    tier2_skip_reason = "No strings found in tier2_fields"
                elif sanitized.metadata.risky_field_names:
                    tier2_skip_reason = "No strings found in Tier 1 risky fields"
                else:
                    tier2_skip_reason = "No strings extracted from tool result"
            else:
                t2_result = self._tier2.classify_by_sentence(combined)
                if not t2_result.get("skipped", True):
                    tier2_score = t2_result["score"]
                    tier2_risk = self._tier2.get_risk_level(tier2_score)
                    max_sentence = t2_result.get("max_sentence")
                else:
                    tier2_skip_reason = t2_result.get("skip_reason")

        # Combine risk levels
        tier1_idx = _RISK_LEVELS.index(sanitized.metadata.overall_risk_level)
        tier2_idx = _RISK_LEVELS.index(tier2_risk)
        risk_level = _RISK_LEVELS[max(tier1_idx, tier2_idx)]

        # Determine whether any threat signals were found (Tier 1 or Tier 2).
        # fields_sanitized captures sanitization methods (role stripping, encoding detection, etc.)
        # that may fire without adding named pattern detections, so we include it here.
        has_threats = (
            len(detections) > 0
            or len(fields_sanitized) > 0
            or (tier2_score is not None and tier2_score >= self._config.tier2.high_risk_threshold)
        )

        # Three cases for allowed:
        # 1. block_high_risk is off -> always allow
        # 2. No threat signals found -> allow (base risk from tool rules alone does not block)
        # 3. Risk did not reach high/critical -> allow
        allowed = not self._config.block_high_risk or not has_threats or risk_level not in ("high", "critical")

        return DefenseResult(
            allowed=allowed,
            risk_level=risk_level,
            sanitized=sanitized.sanitized,
            detections=detections,
            fields_sanitized=fields_sanitized,
            patterns_by_field=prm,
            tier2_score=tier2_score,
            tier2_skip_reason=tier2_skip_reason,
            max_sentence=max_sentence,
            latency_ms=(time.perf_counter() - start_time) * 1000,
        )

    def defend_tool_results(self, items: list[dict[str, Any]]) -> list[DefenseResult]:
        """Defend multiple tool results."""
        return [self.defend_tool_result(item["value"], item["tool_name"]) for item in items]

    def analyze(self, text: str) -> Tier1Result:
        """Analyze text for injection patterns (Tier 1 only)."""
        return self._pattern_detector.analyze(text)

    def get_config(self) -> PromptDefenseConfig:
        return self._config


def create_prompt_defense(**kwargs) -> PromptDefense:
    return PromptDefense(**kwargs)
