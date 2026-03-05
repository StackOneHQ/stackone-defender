"""Encoding Detection.

Detects and handles Base64, URL-encoded, and other encoded content
that might hide injection attempts.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class EncodingDetection:
    type: Literal["base64", "url", "hex", "unicode_escape"]
    original: str
    decoded: str | None = None
    position: int = 0
    length: int = 0
    suspicious: bool = False


@dataclass
class EncodingDetectionResult:
    has_encoding: bool = False
    encoding_types: list[str] = field(default_factory=list)
    detections: list[EncodingDetection] = field(default_factory=list)
    processed_text: str | None = None


_SUSPICIOUS_RE = re.compile(r"system|ignore|instruction|assistant|bypass|override", re.I)


def detect_encoding(
    text: str,
    *,
    min_base64_length: int = 20,
    decode_base64: bool = True,
    decode_url: bool = True,
    action: Literal["flag", "decode", "redact"] = "flag",
    redact_replacement: str = "[ENCODED DATA DETECTED]",
) -> EncodingDetectionResult:
    if not text:
        return EncodingDetectionResult()

    detections: list[EncodingDetection] = []

    if decode_base64:
        detections.extend(_detect_base64(text, min_base64_length))
    if decode_url:
        detections.extend(_detect_url_encoding(text))
    detections.extend(_detect_hex_encoding(text))
    detections.extend(_detect_unicode_escapes(text))

    encoding_types = list({d.type for d in detections})
    result = EncodingDetectionResult(
        has_encoding=bool(detections),
        encoding_types=encoding_types,
        detections=detections,
    )

    if detections and action in ("decode", "redact"):
        result.processed_text = _process_encoded_content(text, detections, action, redact_replacement)

    return result


def _detect_base64(text: str, min_length: int) -> list[EncodingDetection]:
    detections: list[EncodingDetection] = []
    for m in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        candidate = m.group(0)
        if len(candidate) < min_length:
            continue
        try:
            decoded_bytes = base64.b64decode(candidate)
            decoded = decoded_bytes.decode("ascii")
            is_printable = all(0x20 <= ord(c) <= 0x7e or c in "\t\n\r" for c in decoded)
            is_suspicious = is_printable and bool(_SUSPICIOUS_RE.search(decoded))
            detections.append(EncodingDetection(
                type="base64", original=candidate,
                decoded=decoded if is_printable else None,
                position=m.start(), length=len(candidate), suspicious=is_suspicious,
            ))
        except Exception:
            pass
    return detections


def _detect_url_encoding(text: str) -> list[EncodingDetection]:
    detections: list[EncodingDetection] = []
    for m in re.finditer(r"(%[0-9A-Fa-f]{2}){3,}", text):
        candidate = m.group(0)
        try:
            decoded = urllib.parse.unquote(candidate)
            if decoded != candidate:
                is_suspicious = bool(_SUSPICIOUS_RE.search(decoded))
                detections.append(EncodingDetection(
                    type="url", original=candidate, decoded=decoded,
                    position=m.start(), length=len(candidate), suspicious=is_suspicious,
                ))
        except Exception:
            pass
    return detections


def _detect_hex_encoding(text: str) -> list[EncodingDetection]:
    detections: list[EncodingDetection] = []
    for m in re.finditer(r"(\\x[0-9A-Fa-f]{2}){4,}", text):
        candidate = m.group(0)
        try:
            decoded = re.sub(
                r"\\x([0-9A-Fa-f]{2})",
                lambda hm: chr(int(hm.group(1), 16)),
                candidate,
            )
            is_suspicious = bool(_SUSPICIOUS_RE.search(decoded))
            detections.append(EncodingDetection(
                type="hex", original=candidate, decoded=decoded,
                position=m.start(), length=len(candidate), suspicious=is_suspicious,
            ))
        except Exception:
            pass
    return detections


def _detect_unicode_escapes(text: str) -> list[EncodingDetection]:
    detections: list[EncodingDetection] = []
    for m in re.finditer(r"(\\u[0-9A-Fa-f]{4}){3,}", text):
        candidate = m.group(0)
        try:
            decoded = re.sub(
                r"\\u([0-9A-Fa-f]{4})",
                lambda um: chr(int(um.group(1), 16)),
                candidate,
            )
            is_suspicious = bool(_SUSPICIOUS_RE.search(decoded))
            detections.append(EncodingDetection(
                type="unicode_escape", original=candidate, decoded=decoded,
                position=m.start(), length=len(candidate), suspicious=is_suspicious,
            ))
        except Exception:
            pass
    return detections


def _process_encoded_content(
    text: str,
    detections: list[EncodingDetection],
    action: str,
    redact_replacement: str,
) -> str:
    result = text
    # Sort in reverse order by position to preserve earlier positions
    for det in sorted(detections, key=lambda d: d.position, reverse=True):
        replacement = redact_replacement if action == "redact" else (det.decoded or det.original)
        result = result[:det.position] + replacement + result[det.position + det.length:]
    return result


def contains_encoded_content(text: str) -> bool:
    return detect_encoding(text).has_encoding


def contains_suspicious_encoding(text: str) -> bool:
    result = detect_encoding(text)
    return any(d.suspicious for d in result.detections)


def redact_all_encoding(text: str, replacement: str = "[ENCODED DATA DETECTED]") -> str:
    result = detect_encoding(text, action="redact", redact_replacement=replacement)
    return result.processed_text or text


def decode_all_encoding(text: str) -> str:
    """Decode all encoded content in *text*, replacing encoded segments with their decoded form."""
    result = detect_encoding(text, action="decode")
    return result.processed_text or text
