"""Default configuration for the Prompt Defense Framework."""

from __future__ import annotations

import re

from .types import (
    PromptDefenseConfig,
    RiskyFieldConfig,
    Tier2Config,
    ToolSanitizationRule,
    TraversalConfig,
)

DEFAULT_RISKY_FIELDS = RiskyFieldConfig(
    field_names=[
        "name",
        "description",
        "content",
        "title",
        "notes",
        "summary",
        "bio",
        "body",
        "text",
        "message",
        "comment",
        "subject",
    ],
    field_patterns=[
        re.compile(r"_name$"),
        re.compile(r"_description$"),
        re.compile(r"_content$"),
        re.compile(r"_body$"),
        re.compile(r"_notes$"),
        re.compile(r"_summary$"),
        re.compile(r"_bio$"),
        re.compile(r"_text$"),
        re.compile(r"_message$"),
        re.compile(r"_title$"),
    ],
    tool_overrides={
        "documents_*": ["name", "description", "content", "title"],
        "hris_*": ["name", "notes", "bio", "description"],
        "ats_*": ["name", "notes", "description", "summary"],
        "crm_*": ["name", "description", "notes", "content"],
        "gmail_*": ["subject", "body", "snippet", "content"],
        "email_*": ["subject", "body", "snippet", "content"],
        "github_*": ["name", "description", "body", "content", "message", "title"],
    },
)

DEFAULT_TRAVERSAL_CONFIG = TraversalConfig(
    max_depth=10,
    max_size=10 * 1024 * 1024,
    large_array_threshold=1000,
    skip_large_arrays=True,
)

DEFAULT_TOOL_RULES: list[ToolSanitizationRule] = [
    ToolSanitizationRule(
        tool_pattern=re.compile(r"^documents_"),
        sanitization_level="medium",
        max_field_lengths={"name": 500, "description": 2000, "content": 100000},
        skip_fields=["id", "url", "size", "created_at", "updated_at", "mime_type"],
        cumulative_risk_thresholds={"medium": 2, "high": 1, "patterns": 2},
    ),
    ToolSanitizationRule(
        tool_pattern=re.compile(r"^hris_"),
        sanitization_level="medium",
        max_field_lengths={"name": 200, "notes": 2000, "bio": 5000},
        skip_fields=["id", "employee_id", "created_at", "updated_at"],
    ),
    ToolSanitizationRule(
        tool_pattern=re.compile(r"^ats_"),
        sanitization_level="medium",
        max_field_lengths={"name": 200, "notes": 5000, "description": 2000, "summary": 2000},
        skip_fields=["id", "candidate_id", "application_id", "created_at", "updated_at"],
    ),
    ToolSanitizationRule(
        tool_pattern=re.compile(r"^crm_"),
        sanitization_level="medium",
        max_field_lengths={"name": 200, "description": 2000, "notes": 5000, "content": 10000},
        skip_fields=["id", "contact_id", "account_id", "created_at", "updated_at"],
    ),
    ToolSanitizationRule(
        tool_pattern=re.compile(r"^gmail_|^email_"),
        sanitization_level="high",
        max_field_lengths={"subject": 500, "body": 100000, "snippet": 1000},
        skip_fields=["id", "thread_id", "message_id", "date"],
        cumulative_risk_thresholds={"medium": 2, "high": 1, "patterns": 2},
    ),
    ToolSanitizationRule(
        tool_pattern=re.compile(r"^github_"),
        sanitization_level="medium",
        max_field_lengths={"name": 500, "description": 5000, "body": 100000, "content": 100000},
        skip_fields=["id", "sha", "url", "html_url", "created_at", "updated_at"],
    ),
]

DEFAULT_CUMULATIVE_RISK_THRESHOLDS = {"medium": 3, "high": 1, "patterns": 3}

DEFAULT_TIER2_CONFIG = Tier2Config(
    high_risk_threshold=0.8,
    medium_risk_threshold=0.5,
    skip_below_size=50,
)

DEFAULT_CONFIG = PromptDefenseConfig(
    risky_fields=DEFAULT_RISKY_FIELDS,
    traversal=DEFAULT_TRAVERSAL_CONFIG,
    tool_rules=DEFAULT_TOOL_RULES,
    cumulative_risk_thresholds=DEFAULT_CUMULATIVE_RISK_THRESHOLDS,
    tier2=DEFAULT_TIER2_CONFIG,
    block_high_risk=False,
)


def create_config(overrides: dict | None = None) -> PromptDefenseConfig:
    """Create a custom configuration by merging with defaults."""
    if not overrides:
        return PromptDefenseConfig(
            risky_fields=DEFAULT_RISKY_FIELDS,
            traversal=DEFAULT_TRAVERSAL_CONFIG,
            tool_rules=list(DEFAULT_TOOL_RULES),
            cumulative_risk_thresholds=dict(DEFAULT_CUMULATIVE_RISK_THRESHOLDS),
            tier2=Tier2Config(
                high_risk_threshold=DEFAULT_TIER2_CONFIG.high_risk_threshold,
                medium_risk_threshold=DEFAULT_TIER2_CONFIG.medium_risk_threshold,
                skip_below_size=DEFAULT_TIER2_CONFIG.skip_below_size,
            ),
            block_high_risk=False,
        )
    # Simple shallow merge
    config = create_config()
    if "block_high_risk" in overrides:
        config.block_high_risk = overrides["block_high_risk"]
    if "cumulative_risk_thresholds" in overrides:
        config.cumulative_risk_thresholds.update(overrides["cumulative_risk_thresholds"])
    if "tool_rules" in overrides:
        config.tool_rules = overrides["tool_rules"]
    if "tier2" in overrides:
        t2 = overrides["tier2"]
        if isinstance(t2, dict):
            for k, v in t2.items():
                if hasattr(config.tier2, k):
                    setattr(config.tier2, k, v)
        elif isinstance(t2, Tier2Config):
            config.tier2 = t2
    return config
