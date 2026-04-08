# Changelog

## [Unreleased]

### ⚠ BREAKING CHANGES

- Removed per-tool sanitization rules (`ToolSanitizationRule`, `tool_rules` on config and sanitizer, `use_default_tool_rules`, `get_tool_rule`, `should_skip_field`). Behavior matches `@stackone/defender` after removal of tool rules (ENG-12594). Base risk for sanitization comes from `default_risk_level` and Tier 1 outcomes only; cumulative thresholds use `PromptDefenseConfig.cumulative_risk_thresholds`.

### Features

- Tier 2 `classify_by_sentence` now runs sentence scores in a single ONNX `classify_batch` call (parity with TypeScript).
- ONNX model load uses a per-model path lock so concurrent `load_model` calls share one load and the session cache.
