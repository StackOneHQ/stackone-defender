"""Unicode Normalization.

NFKC normalization + homoglyph replacement to prevent bypass attacks.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


def normalize_unicode(text: str) -> str:
    """Normalize Unicode text using NFKC normalization."""
    if not text:
        return text
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _normalize_special_characters(normalized)
    return normalized


_REPLACEMENTS: list[tuple[re.Pattern, str]] = [
    # Zero-width characters
    (re.compile(r"[\u200b-\u200d\ufeff]"), ""),
    # Cyrillic homoglyphs
    (re.compile(r"[\u0430]"), "a"),
    (re.compile(r"[\u0435]"), "e"),
    (re.compile(r"[\u043e]"), "o"),
    (re.compile(r"[\u0440]"), "p"),
    (re.compile(r"[\u0441]"), "c"),
    (re.compile(r"[\u0443]"), "y"),
    (re.compile(r"[\u0445]"), "x"),
    (re.compile(r"[\u0456]"), "i"),
    # Quotes
    (re.compile(r"[\u2018\u2019\u201b\u0060\u00b4]"), "'"),
    (re.compile(r"[\u201c\u201d\u201e\u201f]"), '"'),
    # Dashes
    (re.compile(r"[\u2010-\u2015\u2212]"), "-"),
    # Dots
    (re.compile(r"[\u2024]"), "."),
    (re.compile(r"[\u2026]"), "..."),
    # Colons
    (re.compile(r"[\u02d0]"), ":"),
    (re.compile(r"[\ua789]"), ":"),
]


def _normalize_special_characters(text: str) -> str:
    result = text
    for pattern, replacement in _REPLACEMENTS:
        result = pattern.sub(replacement, result)
    return result


def contains_suspicious_unicode(text: str) -> bool:
    if not text:
        return False
    result = analyze_suspicious_unicode(text)
    return result["has_suspicious"]


@dataclass
class SuspiciousUnicodeAnalysis:
    has_suspicious: bool = False
    zero_width: bool = False
    mixed_script: bool = False
    math_symbols: bool = False
    fullwidth: bool = False


def analyze_suspicious_unicode(text: str) -> dict[str, bool]:
    """Return a detailed breakdown of suspicious Unicode in *text*.

    Returns a dict with keys: has_suspicious, zero_width, mixed_script,
    math_symbols, fullwidth.
    """
    if not text:
        return {"has_suspicious": False, "zero_width": False, "mixed_script": False, "math_symbols": False, "fullwidth": False}

    zero_width = bool(re.search(r"[\u200b-\u200d\ufeff]", text))
    has_cyrillic = bool(re.search(r"[\u0400-\u04ff]", text))
    has_latin = bool(re.search(r"[a-zA-Z]", text))
    mixed_script = has_cyrillic and has_latin
    math_symbols = bool(re.search(r"[\U0001d400-\U0001d7ff]", text))
    fullwidth = bool(re.search(r"[\uff00-\uffef]", text))
    has_suspicious = zero_width or mixed_script or math_symbols or fullwidth

    return {
        "has_suspicious": has_suspicious,
        "zero_width": zero_width,
        "mixed_script": mixed_script,
        "math_symbols": math_symbols,
        "fullwidth": fullwidth,
    }
