## Documentation — End-User Getting Started Guide

Status: Completed — README updated

### Changes
- Added installation and first-run instructions for Windows, Linux, Kali Linux, and macOS
- Documented Python version requirements and virtual environment setup
- Added editable installation instructions using `pip install -e .`
- Added first-run instructions using the built-in synthetic sample data
- Added examples for console, JSON, and HTML reporting
- Added instructions for analyzing existing Nuclei, Trivy, and Nessus scanner exports
- Documented historical risk comparisons using `--history-dir`
- Added test execution instructions and troubleshooting guidance
- Clarified that CTM consumes scanner exports and does not launch scanners or automatically exploit targets

### Scope
Documentation-only update. No application logic changed.

## Phase 6.2 — Input Handling Hardening

Status: Completed — CI passed

### Changes
- Added a shared boolean-normalization helper for common string and numeric representations.
- Fixed asset production parsing so `"false"` is not interpreted as true.
- Fixed boolean parsing for WAF, file validation, antivirus scanning, and MFA controls.
- Hardened exposure-factor calculation for direct calls with string boolean values.
- Added regression tests for asset, control, and exposure boolean handling.
- Added `docs/PHASE_6_2_INPUT_HARDENING.md`.

### Validation
- GitHub Actions CI run #48 passed on the `main` branch.
- Regression tests for context boolean handling are included in `tests/test_context.py`.

### Scope
This phase preserves existing risk modifier values and thresholds. It only makes input handling consistent and predictable; it does not add scanning or exploitation behavior.
