"""Tests for Tier 2 classifier configuration and behavior."""

from stackone_defender.classifiers.tier2_classifier import Tier2Classifier, create_tier2_classifier


class TestTier2ClassifierConfig:
    def test_default_config(self):
        c = Tier2Classifier()
        assert c.get_risk_level(0.9) == "high"
        assert c.get_risk_level(0.6) == "medium"
        assert c.get_risk_level(0.3) == "low"

    def test_custom_thresholds(self):
        c = Tier2Classifier(config={"high_risk_threshold": 0.7, "medium_risk_threshold": 0.4})
        assert c.get_risk_level(0.7) == "high"
        assert c.get_risk_level(0.5) == "medium"
        assert c.get_risk_level(0.3) == "low"

    def test_skip_short_text(self):
        c = Tier2Classifier()
        result = c.classify("hi")
        assert result.skipped
        assert "too short" in (result.skip_reason or "")

    def test_not_ready_without_model(self):
        c = Tier2Classifier(config={"onnx_model_path": "/nonexistent/path"})
        assert not c.is_ready()

    def test_create_factory(self):
        c = create_tier2_classifier()
        assert c.get_risk_level(0.9) == "high"

    def test_get_config(self):
        c = Tier2Classifier()
        cfg = c.get_config()
        assert cfg["high_risk_threshold"] == 0.8
        assert cfg["medium_risk_threshold"] == 0.5
        assert cfg["min_text_length"] == 10
        assert cfg["max_text_length"] == 10000

    def test_get_config_custom(self):
        c = Tier2Classifier(config={"high_risk_threshold": 0.9})
        cfg = c.get_config()
        assert cfg["high_risk_threshold"] == 0.9

    def test_prepare_chunks_short_text_skips(self):
        c = Tier2Classifier()
        prep = c.prepare_chunks("hi")
        assert prep["skipped"]
        assert prep["chunks"] == []

    def test_classify_chunks_batch_passthrough(self):
        c = Tier2Classifier()

        class _FakeOnnx:
            def warmup(self):
                return None

            def classify_batch(self, chunks):
                return [0.1] * len(chunks)

        c._onnx = _FakeOnnx()  # type: ignore[attr-defined]
        assert c.classify_chunks_batch(["a", "b"]) == [0.1, 0.1]
