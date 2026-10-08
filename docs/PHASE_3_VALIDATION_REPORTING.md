# CTM Phase 3 — Scanner Validation and Reporting

Phase 3 validates the complete scanner-to-CTM path using synthetic exports and adds a compact reporting summary.

## Sample exports

Synthetic, non-production samples are included for:

- Nuclei JSONL
- Trivy JSON
- Nessus `.nessus`
- Qualys CSV

These samples are intentionally safe and contain no real credentials or sensitive production data.

## Validation flow

Scanner sample → adapter → normalization → Finding/Asset → STRIDE → MITRE → risk → decision → attack paths → summary.

## Reporting summary

`ctm.scanner_validation.summarize_findings()` reports:

- total findings
- risk-level distribution
- decision distribution
- average score
- highest score
- MITRE techniques
- STRIDE threats

## Why synthetic samples

The repository should not contain real customer scanner exports. Synthetic fixtures make CI reproducible without exposing sensitive infrastructure information.

## Example

```python
from ctm.scanner_engine import run_scanner
from ctm.scanner_validation import summarize_findings

findings = run_scanner(
    "nuclei",
    "mock_inputs/scanner_samples/nuclei_sample.jsonl",
)

summary = summarize_findings(findings)
print(summary)
```

## Scope

Phase 3 validates parsing and end-to-end processing. It does not claim that synthetic findings represent real vulnerabilities or real-world exploitability.
