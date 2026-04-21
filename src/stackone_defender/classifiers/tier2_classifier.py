"""Tier 2 Classifier: ML-based prompt injection detection (ONNX only)."""

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
        if len(text) < self._min_text_length:
            return Tier2Result(
                score=0,
                confidence=0,
                skipped=True,
                skip_reason=f"Text too short ({len(text)} < {self._min_text_length})",
                latency_ms=_ms(start),
            )

        analysis_text = text[: self._max_text_length] if len(text) > self._max_text_length else text

        try:
            score = self._onnx.classify(analysis_text)
            confidence = abs(score - 0.5) * 2
            return Tier2Result(score=score, confidence=confidence, skipped=False, latency_ms=_ms(start))
        except Exception as e:
            return Tier2Result(
                score=0,
                confidence=0,
                skipped=True,
                skip_reason=f"Classification error: {e}",
                latency_ms=_ms(start),
            )

    def classify_batch(self, texts: list[str]) -> list[Tier2Result]:
        return [self.classify(t) for t in texts]

    def classify_by_sentence(self, text: str) -> dict[str, Any]:
        """Classify text by sentence and return max score."""
        start = time.perf_counter()
        sentences = _split_into_sentences(text)
        if not sentences:
            return {"score": 0, "confidence": 0, "skipped": True, "skip_reason": "No sentences found", "latency_ms": _ms(start)}

        original_sentences: list[str] = []
        classifiable: list[str] = []
        for sentence in sentences:
            if len(sentence) < self._min_text_length:
                continue
            original_sentences.append(sentence)
            classifiable.append(
                sentence[: self._max_text_length] if len(sentence) > self._max_text_length else sentence
            )

        if not classifiable:
            return {"score": 0, "confidence": 0, "skipped": True, "skip_reason": "No classifiable sentences", "latency_ms": _ms(start)}

        try:
            scores = self._onnx.classify_batch(classifiable)
        except Exception as e:
            return {
                "score": 0,
                "confidence": 0,
                "skipped": True,
                "skip_reason": f"Classification error: {e}",
                "latency_ms": _ms(start),
            }

        sentence_scores: list[dict[str, Any]] = []
        max_score = 0.0
        max_sentence = ""
        for sentence, score in zip(original_sentences, scores, strict=True):
            safe_score = score if isinstance(score, (int, float)) and score == score else 0.0
            sentence_scores.append({"sentence": sentence, "score": safe_score})
            if safe_score > max_score:
                max_score = safe_score
                max_sentence = sentence

        confidence = abs(max_score - 0.5) * 2
        return {
            "score": max_score,
            "confidence": confidence,
            "skipped": False,
            "latency_ms": _ms(start),
            "max_sentence": max_sentence,
            "sentence_scores": sentence_scores,
        }

    def classify_by_chunks(self, text: str) -> dict[str, Any]:
        start = time.perf_counter()
        if len(text) < self._min_text_length:
            return {"score": 0, "confidence": 0, "skipped": True, "skip_reason": "Text below minTextLength", "latency_ms": _ms(start)}

        model_max_len = self._onnx.get_max_length()
        bounded = text[: self._max_text_length] if len(text) > self._max_text_length else text

        try:
            self._onnx.warmup()
        except Exception as e:
            return {"score": 0, "confidence": 0, "skipped": True, "skip_reason": f"Warmup error: {e}", "latency_ms": _ms(start)}

        try:
            total_tokens = self._onnx.count_tokens(bounded)
        except Exception as e:
            return {"score": 0, "confidence": 0, "skipped": True, "skip_reason": f"Token count error: {e}", "latency_ms": _ms(start)}

        if total_tokens <= model_max_len:
            try:
                score = self._onnx.classify(bounded)
            except Exception as e:
                return {"score": 0, "confidence": 0, "skipped": True, "skip_reason": f"Classification error: {e}", "latency_ms": _ms(start)}
            safe_score = score if isinstance(score, (int, float)) and score == score else 0.0
            return {
                "score": safe_score,
                "confidence": abs(safe_score - 0.5) * 2,
                "skipped": False,
                "max_sentence": bounded,
                "sentence_scores": [{"sentence": bounded, "score": safe_score}],
                "latency_ms": _ms(start),
            }

        max_content_tokens = model_max_len - 2
        sentences = [s for s in _split_into_sentences(bounded) if len(s) >= self._min_text_length]
        if not sentences:
            return {"score": 0, "confidence": 0, "skipped": True, "skip_reason": "No classifiable sentences", "latency_ms": _ms(start)}

        try:
            chunks = self._pack_sentences(sentences, max_content_tokens)
            scores = self._onnx.classify_batch(chunks)
        except Exception as e:
            return {"score": 0, "confidence": 0, "skipped": True, "skip_reason": f"Classification error: {e}", "latency_ms": _ms(start)}

        max_score = 0.0
        max_chunk = ""
        chunk_scores: list[dict[str, Any]] = []
        for i, raw in enumerate(scores):
            safe_score = raw if isinstance(raw, (int, float)) and raw == raw else 0.0
            chunk = chunks[i] if i < len(chunks) else ""
            chunk_scores.append({"sentence": chunk, "score": safe_score})
            if safe_score > max_score:
                max_score = safe_score
                max_chunk = chunk

        return {
            "score": max_score,
            "confidence": abs(max_score - 0.5) * 2,
            "skipped": False,
            "max_sentence": max_chunk,
            "sentence_scores": chunk_scores,
            "latency_ms": _ms(start),
        }

    def prepare_chunks(self, text: str) -> dict[str, Any]:
        if len(text) < self._min_text_length:
            return {"chunks": [], "skipped": True, "skip_reason": "Text below minTextLength"}

        model_max_len = self._onnx.get_max_length()
        bounded = text[: self._max_text_length] if len(text) > self._max_text_length else text
        try:
            self._onnx.warmup()
        except Exception as e:
            return {"chunks": [], "skipped": True, "skip_reason": f"Warmup error: {e}"}

        if len(bounded) + 2 <= model_max_len:
            return {"chunks": [bounded], "skipped": False}

        try:
            total_tokens = self._onnx.count_tokens(bounded)
        except Exception as e:
            return {"chunks": [], "skipped": True, "skip_reason": f"Token count error: {e}"}
        if total_tokens <= model_max_len:
            return {"chunks": [bounded], "skipped": False}

        max_content_tokens = model_max_len - 2
        sentences = [s for s in _split_into_sentences(bounded) if len(s) >= self._min_text_length]
        if not sentences:
            return {"chunks": [], "skipped": True, "skip_reason": "No classifiable sentences"}
        return {"chunks": self._pack_sentences(sentences, max_content_tokens), "skipped": False}

    def classify_chunks_batch(self, chunks: list[str]) -> list[float]:
        if not chunks:
            return []
        self._onnx.warmup()
        return self._onnx.classify_batch(chunks)

    def _pack_sentences(self, sentences: list[str], max_content_tokens: int) -> list[str]:
        chunks: list[str] = []
        current: list[str] = []
        current_tokens = 0

        for sentence in sentences:
            sentence_tokens = self._onnx.count_tokens(sentence)
            sentence_content_tokens = max(0, sentence_tokens - 2)

            if sentence_content_tokens > max_content_tokens:
                if current:
                    chunks.append(" ".join(current))
                    current = []
                    current_tokens = 0
                chunks.append(sentence)
                continue

            if current_tokens + sentence_content_tokens > max_content_tokens:
                chunks.append(" ".join(current))
                current = [sentence]
                current_tokens = sentence_content_tokens
            else:
                current.append(sentence)
                current_tokens += sentence_content_tokens

        if current:
            chunks.append(" ".join(current))

        return chunks

    def is_injection(self, text: str, threshold: float | None = None) -> bool:
        result = self.classify(text)
        if result.skipped:
            return False
        return result.score >= (threshold if threshold is not None else self._medium_risk_threshold)

    def get_config(self) -> dict:
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
