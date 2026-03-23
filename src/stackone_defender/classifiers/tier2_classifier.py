"""Tier 2 Classifier: ML-based prompt injection detection (ONNX only).

Pipeline: text -> Tokenizer -> ONNX Runtime (fine-tuned MiniLM + head) -> logit -> sigmoid -> score
"""

from __future__ import annotations

import re
import time
from typing import Any

from ..types import RiskLevel, Tier2Result
from .onnx_classifier import OnnxClassifier

DEFAULT_TIER2_CLASSIFIER_CONFIG = {
    "high_risk_threshold": 0.8,
    "medium_risk_threshold": 0.5,
    "min_text_length": 10,
    "max_text_length": 10000,
}


class Tier2Classifier:
    """Tier 2 Classifier using ONNX inference."""

    def __init__(self, config: dict | None = None):
        cfg = dict(DEFAULT_TIER2_CLASSIFIER_CONFIG)
        if config:
            cfg.update(config)
        self._high_risk_threshold: float = cfg["high_risk_threshold"]
        self._medium_risk_threshold: float = cfg["medium_risk_threshold"]
        self._min_text_length: int = cfg["min_text_length"]
        self._max_text_length: int = cfg["max_text_length"]
        self._onnx = OnnxClassifier(cfg.get("onnx_model_path"))

    def is_ready(self) -> bool:
        return self._onnx.is_loaded()

    def warmup(self) -> None:
        self._onnx.warmup()

    def classify(self, text: str) -> Tier2Result:
        start = time.perf_counter()

        if not self._onnx.is_loaded():
            try:
                self._onnx.load_model()
            except Exception:
                return Tier2Result(score=0, confidence=0, skipped=True, skip_reason="ONNX model not available", latency_ms=_ms(start))

        if len(text) < self._min_text_length:
            return Tier2Result(
                score=0, confidence=0, skipped=True,
                skip_reason=f"Text too short ({len(text)} < {self._min_text_length})",
                latency_ms=_ms(start),
            )

        analysis_text = text[: self._max_text_length] if len(text) > self._max_text_length else text

        try:
            score = self._onnx.classify(analysis_text)
            confidence = abs(score - 0.5) * 2
            return Tier2Result(score=score, confidence=confidence, skipped=False, latency_ms=_ms(start))
        except Exception as e:
            return Tier2Result(score=0, confidence=0, skipped=True, skip_reason=f"Classification error: {e}", latency_ms=_ms(start))

    def classify_batch(self, texts: list[str]) -> list[Tier2Result]:
        return [self.classify(t) for t in texts]

    def classify_by_sentence(self, text: str) -> dict[str, Any]:
        """Classify text using sentence-level analysis, returning max score."""
        start = time.perf_counter()

        if not self._onnx.is_loaded():
            try:
                self._onnx.load_model()
            except Exception:
                return {
                    "score": 0, "confidence": 0, "skipped": True,
                    "skip_reason": "ONNX model not available", "latency_ms": _ms(start),
                }

        sentences = _split_into_sentences(text)
        if not sentences:
            return {"score": 0, "confidence": 0, "skipped": True, "skip_reason": "No sentences found", "latency_ms": _ms(start)}

        sentence_scores: list[dict[str, Any]] = []
        max_score = 0.0
        max_sentence = ""

        for sentence in sentences:
            if len(sentence) < self._min_text_length:
                continue
            try:
                truncated = sentence[: self._max_text_length] if len(sentence) > self._max_text_length else sentence
                score = self._onnx.classify(truncated)
                sentence_scores.append({"sentence": sentence, "score": score})
                if score > max_score:
                    max_score = score
                    max_sentence = sentence
            except Exception:
                pass

        if not sentence_scores:
            return {"score": 0, "confidence": 0, "skipped": True, "skip_reason": "No classifiable sentences", "latency_ms": _ms(start)}

        confidence = abs(max_score - 0.5) * 2
        return {
            "score": max_score,
            "confidence": confidence,
            "skipped": False,
            "latency_ms": _ms(start),
            "max_sentence": max_sentence,
            "sentence_scores": sentence_scores,
        }

    def is_injection(self, text: str, threshold: float | None = None) -> bool:
        result = self.classify(text)
        if result.skipped:
            return False
        return result.score >= (threshold if threshold is not None else self._medium_risk_threshold)

    def get_config(self) -> dict:
        """Return a copy of the current classifier config."""
        return {
            "high_risk_threshold": self._high_risk_threshold,
            "medium_risk_threshold": self._medium_risk_threshold,
            "min_text_length": self._min_text_length,
            "max_text_length": self._max_text_length,
        }

    def get_risk_level(self, score: float) -> RiskLevel:
        if score >= self._high_risk_threshold:
            return "high"
        if score >= self._medium_risk_threshold:
            return "medium"
        return "low"


def create_tier2_classifier(config: dict | None = None) -> Tier2Classifier:
    return Tier2Classifier(config)


def _ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000


def _split_into_sentences(text: str) -> list[str]:
    """Split text into sentences for granular analysis."""
    sentences: list[str] = []
    chunks = re.split(r"(?<=[.!?])\s+|\n\n+|\n(?=[A-Z0-9#\-*])|(?<=:)\s*\n", text)
    for chunk in chunks:
        trimmed = chunk.strip()
        if not trimmed:
            continue
        if len(trimmed) > 200 and "\n" in trimmed:
            for sub in trimmed.split("\n"):
                sub = sub.strip()
                if sub:
                    sentences.append(sub)
        else:
            sentences.append(trimmed)
    return sentences
