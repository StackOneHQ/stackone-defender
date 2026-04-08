"""stackone-defender: Prompt injection defense for AI tool-calling.

Usage:
    from stackone_defender import create_prompt_defense

    defense = create_prompt_defense(enable_tier2=True)
    defense.warmup_tier2()

    result = defense.defend_tool_result(tool_output, "gmail_get_message")
    if not result.allowed:
        print(f"Blocked: {result.risk_level}")
"""

from .core.prompt_defense import PromptDefense, create_prompt_defense
from .types import DefenseResult, RiskLevel, Tier1Result, ToolSanitizationRule

__all__ = [
    "DefenseResult",
    "PromptDefense",
    "RiskLevel",
    "Tier1Result",
    "ToolSanitizationRule",
    "create_prompt_defense",
]
