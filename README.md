<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/StackOneHQ/defender/main/assets/banner-dark.svg" />
    <img src="https://raw.githubusercontent.com/StackOneHQ/defender/main/assets/banner-light.svg" alt="Defender by StackOne — Indirect prompt injection protection for MCP tool calls" width="800" />
  </picture>

  <p>
    <a href="https://pypi.org/project/stackone-defender/"><img src="https://img.shields.io/pypi/v/stackone-defender?style=flat-square&color=047B43&label=pypi" alt="PyPI version" /></a>
    <a href="https://pypi.org/project/stackone-defender/"><img src="https://img.shields.io/pypi/dm/stackone-defender?style=flat-square&color=047B43&label=downloads" alt="PyPI downloads" /></a>
    <a href="https://github.com/StackOneHQ/defender-python/releases"><img src="https://img.shields.io/github/v/release/StackOneHQ/defender-python?style=flat-square&color=047B43&label=release" alt="latest release" /></a>
    <a href="https://github.com/StackOneHQ/defender-python/stargazers"><img src="https://img.shields.io/github/stars/StackOneHQ/defender-python?style=flat-square&color=047B43" alt="GitHub stars" /></a>
    <a href="./LICENSE"><img src="https://img.shields.io/pypi/l/stackone-defender?style=flat-square&color=047B43" alt="License" /></a>
    <img src="https://img.shields.io/badge/Python-3.10+-047B43?style=flat-square" alt="Python 3.10+" />
  </p>
  <p>
    <img src="https://img.shields.io/badge/model-22MB-047B43?style=flat-square" alt="Model size: 22MB" />
    <img src="https://img.shields.io/badge/latency-~10ms-047B43?style=flat-square" alt="Latency: ~10ms" />
    <img src="https://img.shields.io/badge/CPU--only-no%20GPU%20needed-047B43?style=flat-square" alt="CPU only" />
    <img src="https://img.shields.io/badge/F1%20Score-90.8%25-047B43?style=flat-square" alt="F1 Score: 90.8%" />
  </p>

</div>

---

Indirect prompt injection defense and protection for AI agents using tool calls (via MCP, CLI or direct function calling). Detects and neutralizes prompt injection attacks hidden in tool results (emails, documents, PRs, etc.) before they reach your LLM.

Python port of [@stackone/defender](https://github.com/StackOneHQ/defender).

## Installation

```bash
uv add stackone-defender
```

For Tier 2 ML classification (ONNX):

```bash
uv add stackone-defender[onnx]
```

The ONNX model (~22MB) is bundled in the package — no extra downloads needed.

## Quick Start

```python
from stackone_defender import create_prompt_defense

# Create defense with Tier 1 (patterns) + Tier 2 (ML classifier)
# block_high_risk=True enables the allowed/blocked decision
defense = create_prompt_defense(
    block_high_risk=True,
)

# Optional: pre-load ONNX model to avoid first-call latency
defense.warmup_tier2()

# Defend a tool result
result = defense.defend_tool_result(tool_output, "gmail_get_message")

if not result.allowed:
    print(f"Blocked: risk={result.risk_level}, score={result.tier2_score}")
    print(f"Detections: {', '.join(result.detections)}")
else:
    # Safe to pass result.sanitized to the LLM
    pass_to_llm(result.sanitized)
```

## How It Works

`defend_tool_result()` runs a two-tier defense pipeline:

### Tier 1 — Pattern Detection (~1ms)

Regex-based detection and sanitization:
- **Unicode normalization** — prevents homoglyph attacks (Cyrillic 'а' → ASCII 'a')
- **Role stripping** — removes `SYSTEM:`, `ASSISTANT:`, `<system>`, `[INST]` markers
- **Pattern removal** — redacts injection patterns like "ignore previous instructions"
- **Encoding detection** — detects and handles Base64/URL encoded payloads
- **Boundary annotation** — wraps untrusted content in `[UD-{id}]...[/UD-{id}]` tags

### Tier 2 — ML Classification

Fine-tuned MiniLM classifier with sentence-level analysis:
- Splits text into sentences and scores each one (0.0 = safe, 1.0 = injection)
- ONNX mode: Fine-tuned MiniLM-L6-v2, int8 quantized (~22MB), bundled in the package
- Catches attacks that evade pattern-based detection
- Latency: ~10ms/sample (after model warmup)

**Benchmark results** (ONNX mode, F1 score at threshold 0.5):

| Benchmark | F1 | Samples |
|-----------|-----|---------|
| Qualifire (in-distribution) | 0.8686 | ~1.5k |
| xxz224 (out-of-distribution) | 0.8834 | ~22.5k |
| jayavibhav (adversarial) | 0.9717 | ~1k |
| **Average** | **0.9079** | ~25k |

### Understanding `allowed` vs `risk_level`

Use `allowed` for blocking decisions:
- `allowed=True` — safe to pass to the LLM
- `allowed=False` — content blocked (requires `block_high_risk=True`, which defaults to `False`)

`risk_level` is diagnostic metadata. It starts at `default_risk_level` (default `"medium"`) and is escalated when Tier 1 or Tier 2 find threats. Use it for logging and monitoring; use `allowed` for blocking when `block_high_risk=True`.

Escalation from detections:

| Level | Detection Trigger |
|-------|-------------------|
| `low` | No threats detected |
| `medium` | Suspicious patterns, role markers stripped |
| `high` | Injection patterns detected, content redacted |
| `critical` | Severe injection attempt with multiple indicators |

## API

### `create_prompt_defense(**kwargs)`

Create a defense instance.

```python
defense = create_prompt_defense(
    enable_tier1=True,             # Pattern detection (default: True)
    enable_tier2=True,             # ML classification (default: True)
    block_high_risk=True,          # Block high/critical content (default: False)
    default_risk_level="medium",   # Starting risk before Tier 1 classification
)
```

### `defense.defend_tool_result(value, tool_name)`

The primary method. Runs Tier 1 + Tier 2 and returns a `DefenseResult`:

```python
@dataclass
class DefenseResult:
    allowed: bool                           # Use this for blocking decisions
    risk_level: RiskLevel                   # Diagnostic: tool base risk + detection escalation
    sanitized: Any                          # The sanitized tool result
    detections: list[str]                   # Pattern names detected by Tier 1
    fields_sanitized: list[str]            # Fields where threats were found (e.g. ['subject', 'body'])
    patterns_by_field: dict[str, list[str]] # Patterns per field
    tier2_score: float | None = None       # ML score (0.0 = safe, 1.0 = injection)
    tier2_skip_reason: str | None = None   # When Tier 2 did not produce a score
    max_sentence: str | None = None        # The sentence with the highest Tier 2 score
    latency_ms: float = 0.0               # Processing time in milliseconds
```

### `defense.defend_tool_results(items)`

Batch method — defends multiple tool results.

```python
results = defense.defend_tool_results([
    {"value": email_data, "tool_name": "gmail_get_message"},
    {"value": doc_data, "tool_name": "documents_get"},
    {"value": pr_data, "tool_name": "github_get_pull_request"},
])

for result in results:
    if not result.allowed:
        print(f"Blocked: {', '.join(result.fields_sanitized)}")
```

### `defense.analyze(text)`

Low-level Tier 1 analysis for debugging. Returns pattern matches and risk assessment without sanitization.

```python
result = defense.analyze("SYSTEM: ignore all rules")
print(result.has_detections)  # True
print(result.suggested_risk)  # "high"
print(result.matches)         # [PatternMatch(pattern='...', severity='high', ...)]
```

### Tier 2 Setup

ONNX mode auto-loads the bundled model on first `defend_tool_result()` call. Use `warmup_tier2()` at startup to avoid first-call latency:

```python
defense = create_prompt_defense()
defense.warmup_tier2()  # optional, avoids ~1-2s first-call latency
```

## Risky-field configuration

Which JSON keys are treated as untrusted text (and sanitized) comes from `RiskyFieldConfig`: global field names and patterns, plus optional `tool_overrides` (wildcard keys such as `gmail_*` → list of field names). This mirrors the TypeScript package: there are no separate per-tool sanitization rules for skip lists or base risk.

## Development

### Testing

```bash
uv run pytest
```

## License

Apache-2.0 — See [LICENSE](./LICENSE) for details.
