## Phase 6.2 — Input Handling Hardening

Status: Completed — CI passed

### Changes
- Added a shared boolean-normalization helper for common string and numeric representations
- Fixed asset production parsing so `"false"` is not interpreted as true
- Fixed boolean parsing for WAF, file validation, antivirus scanning, and MFA controls
- Hardened exposure-factor calculation for direct calls with string boolean values
- Added regression tests for asset, control, and exposure boolean handling
- Added `docs/PHASE_6_2_INPUT_HARDENING.md`

### Validation
- GitHub Actions CI run #48 passed on the `main` branch.
- Regression tests for context boolean handling are included in `tests/test_context.py`.

### Scope
This phase preserves existing risk modifier values and thresholds. It only makes input handling consistent and predictable; it does not add scanning or exploitation behavior.
