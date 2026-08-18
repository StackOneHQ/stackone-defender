"""Sentence-level cleaning for the return-both ``sanitized`` copy.

Within a high-risk field, drop the sentences that themselves score high and keep
the rest. Best-effort only (capped by detection) — callers still gate on ``allowed``.
Runs after Tier 2 so per-sentence scores are available.
"""

from __future__ import annotations

from typing import Any

from ..classifiers.tier2_classifier import Tier2Classifier, _split_into_sentences
from ..sanitizers.role_stripper import strip_role_markers
from ..types import DataBoundary
from ..utils.boundary import strip_boundary_patterns, wrap_with_boundary


def _clean_field(raw: str, tier2: Tier2Classifier, high_threshold: float) -> str:
    sentences = _split_into_sentences(raw)
    # A single sentence can't be isolated to a bad part, and benign opaque tokens read
    # as one sentence — leave it untouched; the verdict/``allowed`` still gates it.
    if len(sentences) <= 1:
        return raw
    scores = tier2.classify_chunks_batch(sentences)
    kept = [s for s, sc in zip(sentences, scores, strict=False) if sc < high_threshold]
    # Every sentence flagged — drop them all rather than blocking the field wholesale.
    if not kept:
        return ""
    # Strip role markers from survivors as defense-in-depth against a sub-threshold marker.
    return strip_role_markers(" ".join(kept)).strip()


def clean_high_risk_content(
    content: Any,
    high_risk_values: set[str],
    tier2: Tier2Classifier,
    high_threshold: float,
    boundary: DataBoundary | None = None,
) -> Any:
    """Clone ``content`` (already structurally protected, optionally boundary-wrapped)
    and replace only the leaf strings whose unwrapped value is in ``high_risk_values``
    with a sentence-cleaned version."""
    if not high_risk_values:
        return content

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            raw = strip_boundary_patterns(value) if boundary else value
            if raw not in high_risk_values:
                return value
            cleaned = _clean_field(raw, tier2, high_threshold)
            return wrap_with_boundary(cleaned, boundary) if boundary else cleaned
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        return value

    return walk(content)
