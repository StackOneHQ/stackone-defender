"""Role Marker Stripping.

Removes role markers that could confuse the LLM into treating
user data as system/assistant messages.
"""

from __future__ import annotations

import re

_ROLE_MARKERS = [
    re.compile(r"^SYSTEM:\s*", re.I | re.M),
    re.compile(r"^ASSISTANT:\s*", re.I | re.M),
    re.compile(r"^USER:\s*", re.I | re.M),
    re.compile(r"^DEVELOPER:\s*", re.I | re.M),
    re.compile(r"^ADMIN(?:ISTRATOR)?:\s*", re.I | re.M),
    re.compile(r"^INSTRUCTIONS?:\s*", re.I | re.M),
    re.compile(r"^HUMAN:\s*", re.I | re.M),
    re.compile(r"^AI:\s*", re.I | re.M),
    re.compile(r"^BOT:\s*", re.I | re.M),
    re.compile(r"^CLAUDE:\s*", re.I | re.M),
    re.compile(r"^GPT:\s*", re.I | re.M),
    re.compile(r"^CHATGPT:\s*", re.I | re.M),
]

_INLINE_ROLE_MARKERS = [
    re.compile(r"\bSYSTEM:\s*", re.I),
    re.compile(r"\bASSISTANT:\s*", re.I),
    re.compile(r"\bINSTRUCTIONS?:\s*", re.I),
]

_XML_ROLE_TAGS = [
    re.compile(r"</?system>", re.I),
    re.compile(r"</?assistant>", re.I),
    re.compile(r"</?user>", re.I),
    re.compile(r"</?instruction>", re.I),
    re.compile(r"</?prompt>", re.I),
    re.compile(r"</?admin>", re.I),
    re.compile(r"</?developer>", re.I),
]

_BRACKET_MARKERS = [
    re.compile(r"\[SYSTEM\]", re.I),
    re.compile(r"\[/SYSTEM\]", re.I),
    re.compile(r"\[INST\]", re.I),
    re.compile(r"\[/INST\]", re.I),
    re.compile(r"\[INSTRUCTION\]", re.I),
    re.compile(r"\[/INSTRUCTION\]", re.I),
    re.compile(r"\[\[SYSTEM\]\]", re.I),
    re.compile(r"\[\[/SYSTEM\]\]", re.I),
]


def strip_role_markers(
    text: str,
    *,
    start_only: bool = False,
    strip_xml_tags: bool = True,
    strip_bracket_markers: bool = True,
    custom_markers: list[re.Pattern] | None = None,
) -> str:
    if not text:
        return text

    result = text
    for p in _ROLE_MARKERS:
        result = p.sub("", result)

    if not start_only:
        for p in _INLINE_ROLE_MARKERS:
            result = p.sub("", result)

    if strip_xml_tags:
        for p in _XML_ROLE_TAGS:
            result = p.sub("", result)

    if strip_bracket_markers:
        for p in _BRACKET_MARKERS:
            result = p.sub("", result)

    if custom_markers:
        for p in custom_markers:
            result = p.sub("", result)

    result = re.sub(r"\s{2,}", " ", result).strip()
    return result


def contains_role_markers(text: str) -> bool:
    if not text:
        return False
    all_patterns = _ROLE_MARKERS + _INLINE_ROLE_MARKERS + _XML_ROLE_TAGS + _BRACKET_MARKERS
    return any(p.search(text) for p in all_patterns)


def find_role_markers(text: str) -> list[str]:
    if not text:
        return []
    found: set[str] = set()
    all_patterns = _ROLE_MARKERS + _INLINE_ROLE_MARKERS + _XML_ROLE_TAGS + _BRACKET_MARKERS
    for p in all_patterns:
        for m in p.finditer(text):
            found.add(m.group(0).strip())
    return list(found)
