"""ONNX classifier for fine-tuned MiniLM prompt injection detection.

Pipeline: text -> tokenizer -> ONNX Runtime -> logit -> sigmoid -> score
"""

from __future__ import annotations

import math
from pathlib import Path


def _default_model_path() -> str:
    """Return path to the bundled ONNX model directory."""
    return str(Path(__file__).resolve().parent.parent / "models" / "minilm-full-aug")


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


class OnnxClassifier:
    """ONNX Classifier for fine-tuned MiniLM models."""

    def __init__(self, model_path: str | None = None):
        self._model_path = model_path or _default_model_path()
        self._session = None
        self._tokenizer = None
        self._max_length = 256
        self._load_failed = False

    def load_model(self, model_path: str | None = None) -> None:
        if model_path:
            self._model_path = model_path
        if self._session is not None and self._tokenizer is not None:
            return
        if self._load_failed:
            raise ImportError("ONNX dependencies not installed. Install with: pip install stackone-defender[onnx]")
        self._load_model()

    def _load_model(self) -> None:
        try:
            import numpy as np  # noqa: F401
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as e:
            self._load_failed = True
            raise ImportError(
                "ONNX dependencies not installed. Install with: pip install stackone-defender[onnx]"
            ) from e

        tokenizer_path = str(Path(self._model_path) / "tokenizer.json")
        self._tokenizer = Tokenizer.from_file(tokenizer_path)
        self._tokenizer.enable_truncation(max_length=self._max_length)
        self._tokenizer.enable_padding(length=self._max_length)

        onnx_path = str(Path(self._model_path) / "model_quantized.onnx")
        self._session = ort.InferenceSession(onnx_path)

    def classify(self, text: str) -> float:
        """Classify a single text, returning a sigmoid score in [0, 1]."""
        self._ensure_loaded()
        import numpy as np

        encoding = self._tokenizer.encode(text)
        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

        results = self._session.run(None, {"input_ids": input_ids, "attention_mask": attention_mask})
        logit = float(results[0][0][0])
        return _sigmoid(logit)

    def classify_batch(self, texts: list[str]) -> list[float]:
        """Classify multiple texts in batch."""
        if not texts:
            return []
        self._ensure_loaded()
        import numpy as np

        encodings = self._tokenizer.encode_batch(texts)
        input_ids = np.array([e.ids for e in encodings], dtype=np.int64)
        attention_mask = np.array([e.attention_mask for e in encodings], dtype=np.int64)

        results = self._session.run(None, {"input_ids": input_ids, "attention_mask": attention_mask})
        logits = results[0]
        return [_sigmoid(float(logits[i][0])) for i in range(len(texts))]

    def warmup(self) -> None:
        self.load_model()

    def is_loaded(self) -> bool:
        return self._session is not None and self._tokenizer is not None

    def _ensure_loaded(self) -> None:
        if not self.is_loaded():
            self.load_model()
