## Phase 6.2 — Input Handling Hardening

Status: Implemented in patch — pending upload and CI verification

### Changes
- Added a shared boolean-normalization helper for common string and numeric representations
- Fixed asset production parsing so `"false"` is not interpreted as true
- Fixed boolean parsing for WAF, file validation, antivirus scanning, and MFA controls
- Hardened exposure-factor calculation for direct calls with string boolean values
- Added regression tests for asset, control, and exposure boolean handling
- Added `docs/PHASE_6_2_INPUT_HARDENING.md`

### Scope
This phase preserves existing risk modifier values and thresholds. It only makes input handling consistent and predictable; it does not add scanning or exploitation behavior.
