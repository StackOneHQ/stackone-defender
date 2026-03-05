"""Shared injection pattern definitions.

These patterns are used by both Tier 1 classification and sanitization.
Single source of truth for pattern matching.
"""

from __future__ import annotations

import re

from ..types import PatternDefinition

# ---------------------------------------------------------------------------
# Role markers
# ---------------------------------------------------------------------------
ROLE_MARKER_PATTERNS: list[PatternDefinition] = [
    PatternDefinition("role_system", re.compile(r"^SYSTEM:\s*", re.I), "role_marker", "high", "System role marker at start of text"),
    PatternDefinition("role_assistant", re.compile(r"^ASSISTANT:\s*", re.I), "role_marker", "high", "Assistant role marker at start of text"),
    PatternDefinition("role_user", re.compile(r"^USER:\s*", re.I), "role_marker", "medium", "User role marker at start of text"),
    PatternDefinition("role_developer", re.compile(r"^DEVELOPER:\s*", re.I), "role_marker", "high", "Developer role marker at start of text"),
    PatternDefinition("role_admin", re.compile(r"^ADMIN(?:ISTRATOR)?:\s*", re.I), "role_marker", "high", "Admin role marker at start of text"),
    PatternDefinition("role_instruction", re.compile(r"^INSTRUCTIONS?:\s*", re.I), "role_marker", "high", "Instruction marker at start of text"),
    PatternDefinition("role_human", re.compile(r"^HUMAN:\s*", re.I), "role_marker", "medium", "Human role marker at start of text"),
    PatternDefinition("role_ai", re.compile(r"^AI:\s*", re.I), "role_marker", "medium", "AI role marker at start of text"),
    # Bracketed variants
    PatternDefinition("role_system_bracket", re.compile(r"^\[SYSTEM\]", re.I), "role_marker", "high", "Bracketed system role marker"),
    PatternDefinition("role_inst_bracket", re.compile(r"^\[INST\]", re.I), "role_marker", "high", "Bracketed instruction marker (Llama format)"),
    # XML-style variants
    PatternDefinition("role_system_xml", re.compile(r"<system>", re.I), "role_marker", "high", "XML-style system tag"),
    PatternDefinition("role_assistant_xml", re.compile(r"<assistant>", re.I), "role_marker", "medium", "XML-style assistant tag"),
]

# ---------------------------------------------------------------------------
# Instruction overrides
# ---------------------------------------------------------------------------
INSTRUCTION_OVERRIDE_PATTERNS: list[PatternDefinition] = [
    PatternDefinition("ignore_previous", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|earlier|above)\s+(?:instructions?|prompts?|rules?|guidelines?|directions?)", re.I), "instruction_override", "high", "Attempt to ignore previous instructions"),
    PatternDefinition("forget_previous", re.compile(r"forget\s+(?:all\s+)?(?:(?:previous|prior|earlier|above)\s+)?(?:instructions?|prompts?|rules?|context|guidelines?)", re.I), "instruction_override", "high", "Attempt to make AI forget instructions"),
    PatternDefinition("disregard_previous", re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior|earlier|above)\s+(?:instructions?|prompts?|rules?)", re.I), "instruction_override", "high", "Attempt to disregard instructions"),
    PatternDefinition("override_instructions", re.compile(r"override\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?)", re.I), "instruction_override", "high", "Direct override attempt"),
    PatternDefinition("new_instructions", re.compile(r"new\s+instructions?:\s*", re.I), "instruction_override", "high", "Attempt to inject new instructions"),
    PatternDefinition("updated_instructions", re.compile(r"(?:updated?|revised?|changed?)\s+instructions?:\s*", re.I), "instruction_override", "high", "Attempt to update instructions"),
    PatternDefinition("stop_being", re.compile(r"stop\s+being\s+(?:a\s+)?(?:helpful|assistant|ai|chatbot)", re.I), "instruction_override", "medium", "Attempt to change AI behavior"),
    PatternDefinition("from_now_on", re.compile(r"from\s+now\s+on,?\s+(?:you\s+)?(?:will|must|should|are)", re.I), "instruction_override", "medium", "Attempt to set new behavior"),
]

# ---------------------------------------------------------------------------
# Role assumption
# ---------------------------------------------------------------------------
ROLE_ASSUMPTION_PATTERNS: list[PatternDefinition] = [
    PatternDefinition("you_are_now", re.compile(r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|the|my)?", re.I), "role_assumption", "high", "Attempt to assign new role"),
    PatternDefinition("act_as", re.compile(r"act\s+(?:as|like)\s+(?:a\s+)?(?:system|admin|developer|root|superuser)", re.I), "role_assumption", "high", "Attempt to make AI act as privileged role"),
    PatternDefinition("pretend_to_be", re.compile(r"pretend\s+(?:to\s+be|you\s+are)\s+(?:a\s+)?", re.I), "role_assumption", "medium", "Attempt to make AI pretend"),
    PatternDefinition("roleplay_as", re.compile(r"roleplay\s+(?:as|like)\s+(?:a\s+)?", re.I), "role_assumption", "low", "Roleplay request (lower severity)"),
    PatternDefinition("imagine_you_are", re.compile(r"imagine\s+(?:that\s+)?you\s+are\s+(?:a\s+)?", re.I), "role_assumption", "low", "Imagination prompt (lower severity)"),
    PatternDefinition("jailbreak_dan", re.compile(r"\bDAN\b.*?(?:do\s+anything|jailbreak)", re.I), "role_assumption", "high", "DAN jailbreak attempt"),
    PatternDefinition("developer_mode", re.compile(r"developer\s+mode\s+(?:is\s+)?(?:now\s+)?(?:enabled?|activated?|on)", re.I), "role_assumption", "high", "Developer mode activation attempt"),
]

# ---------------------------------------------------------------------------
# Security bypass
# ---------------------------------------------------------------------------
SECURITY_BYPASS_PATTERNS: list[PatternDefinition] = [
    PatternDefinition("bypass_security", re.compile(r"bypass\s+(?:the\s+)?(?:security|safety|guardrails?|filters?|restrictions?)", re.I), "security_bypass", "high", "Direct security bypass attempt"),
    PatternDefinition("disable_safety", re.compile(r"disable\s+(?:the\s+)?(?:safety|security|guardrails?|filters?|restrictions?)", re.I), "security_bypass", "high", "Attempt to disable safety features"),
    PatternDefinition("ignore_safety", re.compile(r"ignore\s+(?:the\s+)?(?:safety|security|ethical)\s+(?:guidelines?|rules?|restrictions?)", re.I), "security_bypass", "high", "Attempt to ignore safety guidelines"),
    PatternDefinition("no_restrictions", re.compile(r"(?:without|no)\s+(?:any\s+)?(?:restrictions?|limitations?|guardrails?|filters?)", re.I), "security_bypass", "medium", "Request for unrestricted response"),
    PatternDefinition("uncensored", re.compile(r"(?:uncensored|unfiltered|unrestricted)\s*(?:mode|response|output|version)?", re.I), "security_bypass", "high", "Request for uncensored mode"),
]

# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------
COMMAND_EXECUTION_PATTERNS: list[PatternDefinition] = [
    PatternDefinition("execute_command", re.compile(r"execute\s+(?:the\s+)?(?:following|this|these)\s+(?:command|instruction|code)", re.I), "command_execution", "high", "Command execution instruction"),
    PatternDefinition("run_code", re.compile(r"run\s+(?:the\s+)?(?:following|this|these)\s+(?:code|script|command)", re.I), "command_execution", "high", "Code execution instruction"),
    PatternDefinition("eval_expression", re.compile(r"eval(?:uate)?\s*\(", re.I), "command_execution", "medium", "Eval function pattern"),
    PatternDefinition("shell_command", re.compile(r"\$\([^)]+\)|`[^`]+`"), "command_execution", "medium", "Shell command substitution"),
]

# ---------------------------------------------------------------------------
# Encoding suspicious
# ---------------------------------------------------------------------------
ENCODING_SUSPICIOUS_PATTERNS: list[PatternDefinition] = [
    PatternDefinition("base64_instruction", re.compile(r"(?:decode|base64)\s*[:(]\s*[A-Za-z0-9+/=]{20,}", re.I), "encoding_suspicious", "high", "Base64 encoded content with decode instruction"),
    PatternDefinition("hex_escape_sequence", re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}"), "encoding_suspicious", "medium", "Hex escape sequence (potential obfuscation)"),
    PatternDefinition("unicode_escape_sequence", re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}"), "encoding_suspicious", "medium", "Unicode escape sequence (potential obfuscation)"),
    PatternDefinition("html_entity_abuse", re.compile(r"(?:&#\d{2,4};){4,}|(?:&#x[0-9a-fA-F]{2,4};){4,}", re.I), "encoding_suspicious", "medium", "HTML entity encoding (potential obfuscation)"),
    PatternDefinition("rot13_mention", re.compile(r"rot13|caesar\s+cipher|decode\s+this", re.I), "encoding_suspicious", "low", "Mention of simple encoding schemes"),
    PatternDefinition("leetspeak_injection", re.compile(r"1gn0r3|f0rg3t|byp4ss|syst3m|4dm1n|h4ck", re.I), "encoding_suspicious", "medium", "Leetspeak obfuscation of injection keywords"),
]

# ---------------------------------------------------------------------------
# Prompt leaking
# ---------------------------------------------------------------------------
PROMPT_LEAKING_PATTERNS: list[PatternDefinition] = [
    PatternDefinition("reveal_system_prompt", re.compile(r"reveal\s+(?:your\s+)?(?:system\s+)?prompt", re.I), "instruction_override", "high", "Attempt to reveal system prompt"),
    PatternDefinition("show_instructions", re.compile(r"show\s+(?:me\s+)?(?:your\s+)?(?:(?:initial|original|system|hidden)\s+)?instructions?", re.I), "instruction_override", "high", "Attempt to show hidden instructions"),
    PatternDefinition("print_above", re.compile(r"print\s+(?:everything|all|text)\s+(?:above|before)", re.I), "instruction_override", "high", "Attempt to print content above current context"),
    PatternDefinition("repeat_back", re.compile(r"repeat\s+(?:back\s+)?(?:everything|all|your\s+instructions?)", re.I), "instruction_override", "high", "Attempt to make AI repeat instructions"),
    PatternDefinition("what_are_your_instructions", re.compile(r"what\s+(?:are|were)\s+(?:your|the)\s+(?:(?:initial|original|system)\s+)?instructions?", re.I), "instruction_override", "medium", "Question about system instructions"),
    PatternDefinition("output_initialization", re.compile(r"output\s+(?:your\s+)?(?:initialization|init|startup|boot)", re.I), "instruction_override", "high", "Attempt to output initialization content"),
]

# ---------------------------------------------------------------------------
# Indirect injection
# ---------------------------------------------------------------------------
INDIRECT_INJECTION_PATTERNS: list[PatternDefinition] = [
    PatternDefinition("markdown_hidden_instruction", re.compile(r"\[.*?\]\(.*?(?:ignore|forget|system|instruction).*?\)", re.I), "structural", "high", "Markdown link with hidden injection"),
    PatternDefinition("html_comment_injection", re.compile(r"<!--\s*(?:system|ignore|instruction|prompt).*?-->", re.I), "structural", "high", "HTML comment containing injection keywords"),
    PatternDefinition("invisible_unicode", re.compile(r"[\u200b-\u200d\ufeff\u2060\u2061\u2062\u2063\u2064]"), "encoding_suspicious", "medium", "Invisible Unicode characters (zero-width, etc.)"),
    PatternDefinition("text_direction_override", re.compile(r"[\u202a-\u202e\u2066-\u2069]"), "encoding_suspicious", "medium", "Text direction override characters"),
    PatternDefinition("confusable_homoglyphs", re.compile(r"[\u13a0-\u13f4]|[\u1d00-\u1d2b]|[\u0400-\u04ff]"), "encoding_suspicious", "medium", "Unicode homoglyph characters (Cherokee, Small Caps, Cyrillic)"),
    PatternDefinition("separator_injection", re.compile(r"[-=]{10,}[^-=\n]*(?:system|instruction|ignore)", re.I), "structural", "medium", "Separator followed by injection attempt"),
    PatternDefinition("json_injection", re.compile(r'"(?:system|role|instruction|prompt)"\s*:\s*"', re.I), "structural", "medium", "JSON-style role/instruction injection"),
]

# ---------------------------------------------------------------------------
# All patterns combined
# ---------------------------------------------------------------------------
ALL_PATTERNS: list[PatternDefinition] = [
    *ROLE_MARKER_PATTERNS,
    *INSTRUCTION_OVERRIDE_PATTERNS,
    *ROLE_ASSUMPTION_PATTERNS,
    *SECURITY_BYPASS_PATTERNS,
    *COMMAND_EXECUTION_PATTERNS,
    *ENCODING_SUSPICIOUS_PATTERNS,
    *PROMPT_LEAKING_PATTERNS,
    *INDIRECT_INJECTION_PATTERNS,
]


def get_patterns_by_category(category: str) -> list[PatternDefinition]:
    return [p for p in ALL_PATTERNS if p.category == category]


def get_patterns_by_severity(severity: str) -> list[PatternDefinition]:
    return [p for p in ALL_PATTERNS if p.severity == severity]


FAST_FILTER_KEYWORDS: list[str] = [
    # Role markers
    "system:", "assistant:", "user:", "developer:", "admin:",
    "instruction", "[system]", "[inst]", "<system>", "<assistant>",
    # Override keywords
    "ignore", "forget", "disregard", "override", "bypass",
    "disable", "stop being", "from now on",
    # Role assumption
    "you are now", "act as", "pretend", "roleplay", "jailbreak",
    "dan", "developer mode", "imagine you",
    # Security bypass
    "uncensored", "unfiltered", "unrestricted",
    "no restrictions", "without restrictions",
    # Commands
    "execute", "eval(", "$(", "run the",
    # Encoding/obfuscation
    "base64", "decode", "\\x", "\\u", "&#", "rot13",
    "1gn0r3", "f0rg3t", "byp4ss",
    # Prompt leaking
    "reveal", "show me your", "print everything", "print above",
    "repeat back", "what are your instructions", "output initialization",
    # Indirect injection
    "<!--", '"system"', '"role"', '"instruction"',
]


def contains_filter_keywords(text: str) -> bool:
    """Check if text contains any fast filter keywords (case-insensitive)."""
    lower = text.lower()
    return any(kw.lower() in lower for kw in FAST_FILTER_KEYWORDS)
