# Phase 6.2 — Input Handling Hardening

## Goal

Ensure direct context helpers interpret common boolean representations consistently. In Python, `bool("false")` evaluates to `True`, which can silently skew exposure context, production metadata, and control-adjusted risk.

## Changes

- Added a shared `as_bool` helper for booleans, common true/false strings, numeric values, and defaults.
- Hardened asset production parsing so values such as `"false"` remain false.
- Hardened WAF, file validation, antivirus scanning, and MFA control parsing.
- Hardened exposure-factor calculation when called directly with string boolean values.
- Added regression tests for true/false strings in asset, control, and exposure context.
- Preserved existing risk modifier values and the strong security-header control behavior.

## Validation

Run the full suite from the repository root:

```bash
python -m pytest -q
```

GitHub Actions should also pass on the configured Python versions before this phase is marked complete.

## Scope and safety boundary

This phase only normalizes input values and tests their effect on existing calculations. It does not change risk thresholds, scanner behavior, threat mappings, or attack-path claims.
