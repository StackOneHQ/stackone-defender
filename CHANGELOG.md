# Changelog

## [0.6.1](https://github.com/StackOneHQ/stackone-defender/compare/stackone-defender-v0.1.2...stackone-defender-v0.6.1) (2026-04-21)

### Features

* align Python package behavior with `@stackone/defender` 0.6.1
* add SFE preprocessing support (`use_sfe`) with fail-open optional runtime loading
* add packed-chunk Tier 2 batching and density-adjusted scoring
* add dangerous-key traversal hardening (`__proto__`, `constructor`, `prototype`)
* add cumulative-risk fractional thresholds to reduce list-response false positives

### Breaking Changes

* Python package version jumps from `0.1.2` to `0.6.1` to align release train with TypeScript parity.
* `DefenseResult` now includes `fields_dropped` and `truncated_at_depth`.

## [0.1.2](https://github.com/StackOneHQ/stackone-defender/compare/stackone-defender-v0.1.1...stackone-defender-v0.1.2) (2026-04-08)


### Bug Fixes

* upgrade ML classifier to jbv2 (AgentShield 73.7 → 79.8) ([b452b39](https://github.com/StackOneHQ/stackone-defender/commit/b452b39c718329355f50c418bd50c37da2ed8698))


### Documentation

* update README to reflect changes in package name and Python version ([d2fc2ca](https://github.com/StackOneHQ/stackone-defender/commit/d2fc2ca1900e2f6410df2ec075c5a8a1c3ac241b))

## [0.1.1](https://github.com/StackOneHQ/stackone-defender/compare/stackone-defender-v0.1.0...stackone-defender-v0.1.1) (2026-04-08)


### Features

* add missing functions for full TS API parity ([aec0c5b](https://github.com/StackOneHQ/stackone-defender/commit/aec0c5b8d31715df7e4ec2e4d306b55d595bb1c3))
* add PyPI publishing setup with Release Please CI ([2e28373](https://github.com/StackOneHQ/stackone-defender/commit/2e28373a27315dbb5e7deb23621977fe7fa2f7bc))
* add tier2_fields filter and export ToolSanitizationRule ([cb7fd93](https://github.com/StackOneHQ/stackone-defender/commit/cb7fd93fb88a30f40edc171ef3fcdc5d6ce2534d))
* **ENG-12402:** add PyPI publishing setup with Release Please CI ([f979748](https://github.com/StackOneHQ/stackone-defender/commit/f979748a8a3b2084ea241c352866adcfcd0145ea))
* port stackone-defender from TypeScript to Python ([e3ff70d](https://github.com/StackOneHQ/stackone-defender/commit/e3ff70dd6a0bc94578dc4dbfde87c5d75f00b7b8))
* **sanitizer:** remove dead use_tier2_classification from ToolResultSanitizer ([4646179](https://github.com/StackOneHQ/stackone-defender/commit/46461798fcf5acc6ac6e23bc65177c35d9353d9c))
* sync Python package with TypeScript parity ([e1836dd](https://github.com/StackOneHQ/stackone-defender/commit/e1836dd967ad23997983ef1607118d1a25807e1c))


### Bug Fixes

* **classifier:** surface classification errors in classify_by_sentence skip_reason ([bd94639](https://github.com/StackOneHQ/stackone-defender/commit/bd9463978dac5572f999d8ec3ed1adbaf0bb97f2))
* **defender:** fix _extract_strings filtering, None checks, and cache ONNX load failure ([bf4ce99](https://github.com/StackOneHQ/stackone-defender/commit/bf4ce993287db9e067b661100b5bd92cc21aef6b))
* **defender:** sync hasThreats blocking logic and tool rules precedence from JS package ([a217c3e](https://github.com/StackOneHQ/stackone-defender/commit/a217c3ef27aa0e4d92f21571bf0559ff9906f660))
* enable tier2 by default to match TypeScript package ([f1fe990](https://github.com/StackOneHQ/stackone-defender/commit/f1fe990e1a81c32cb271f6ca85cc063f3da49223))
* sync Python with TypeScript parity ([cec0813](https://github.com/StackOneHQ/stackone-defender/commit/cec0813ff8cc98f4502d5916d285a28877983d98))
* use uv instead of pip in README installation instructions ([519759f](https://github.com/StackOneHQ/stackone-defender/commit/519759f09c6fc1eb6bf97f53ad0cbd25c78e2893))


### Documentation

* add README adapted from TypeScript package ([a03c757](https://github.com/StackOneHQ/stackone-defender/commit/a03c757a1760b797d9a3ef444950e2839ca1c52d))

## Changelog
