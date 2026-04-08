"""Default configuration for the Prompt Defense Framework."""

from __future__ import annotations

import re

from .types import PromptDefenseConfig, RiskyFieldConfig, Tier2Config, TraversalConfig

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

DEFAULT_CUMULATIVE_RISK_THRESHOLDS = {"medium": 3, "high": 1, "patterns": 3}

DEFAULT_TIER2_CONFIG = Tier2Config(
    high_risk_threshold=0.8,
    medium_risk_threshold=0.5,
    skip_below_size=50,
)

DEFAULT_CONFIG = PromptDefenseConfig(
    risky_fields=DEFAULT_RISKY_FIELDS,
    traversal=DEFAULT_TRAVERSAL_CONFIG,
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
            cumulative_risk_thresholds=dict(DEFAULT_CUMULATIVE_RISK_THRESHOLDS),
            tier2=Tier2Config(
                high_risk_threshold=DEFAULT_TIER2_CONFIG.high_risk_threshold,
                medium_risk_threshold=DEFAULT_TIER2_CONFIG.medium_risk_threshold,
                skip_below_size=DEFAULT_TIER2_CONFIG.skip_below_size,
                min_text_length=DEFAULT_TIER2_CONFIG.min_text_length,
                max_text_length=DEFAULT_TIER2_CONFIG.max_text_length,
                onnx_model_path=DEFAULT_TIER2_CONFIG.onnx_model_path,
                tier2_fields=DEFAULT_TIER2_CONFIG.tier2_fields,
            ),
            block_high_risk=False,
        )
    # Simple shallow merge
    config = create_config()
    if "block_high_risk" in overrides:
        config.block_high_risk = overrides["block_high_risk"]
    if "cumulative_risk_thresholds" in overrides:
        config.cumulative_risk_thresholds.update(overrides["cumulative_risk_thresholds"])
    if "tier2" in overrides:
        t2 = overrides["tier2"]
        if isinstance(t2, dict):
            for k, v in t2.items():
                if hasattr(config.tier2, k):
                    setattr(config.tier2, k, v)
        elif isinstance(t2, Tier2Config):
            config.tier2 = t2
    return config
