## Phase 6.4 — Scanner Severity and XML Parsing CI Fix

Status: Fix prepared for validation; GitHub Actions must pass after upload.

### Changes
- Routed scanner finding severity through the shared source-aware severity normalizer.
- Preserved scanner-provided `risk_factor` in normalized vulnerability data.
- Switched Nessus and Qualys XML adapters to `defusedxml.ElementTree` to reject unsafe entity declarations.
- Kept the Qualys CSV parsing path unchanged.

### Validation
- Targeted by `tests/test_severity_normalization.py` and `tests/test_xml_hardening.py`.
- Run the GitHub Actions workflow after uploading these files. Do not mark this phase complete until all supported Python jobs pass.
