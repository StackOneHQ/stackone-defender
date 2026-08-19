"""Detection helpers (detect-and-gate — no content mutation)."""

from .encoding_detector import (
    contains_suspicious_encoding,
    decode_all_levels,
    detect_encoding,
)
from .normalizer import normalize_unicode

__all__ = [
    "contains_suspicious_encoding",
    "decode_all_levels",
    "detect_encoding",
    "normalize_unicode",
]
