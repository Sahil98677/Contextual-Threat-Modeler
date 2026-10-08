# CTM Phase 3.1 — End-to-End Scanner Validation

Phase 3.1 turns the synthetic scanner fixtures from parsing examples into regression coverage for the complete CTM scanner pipeline.

## Covered scanners

- Nuclei JSONL
- Trivy JSON
- Nessus `.nessus` XML
- Qualys CSV

## Validation path

```text
Synthetic Export
      ↓
Scanner Adapter
      ↓
Neutral Scanner Records
      ↓
CTM Normalization
      ↓
Asset + Finding
      ↓
STRIDE + MITRE
      ↓
Likelihood + Impact + Controls
      ↓
Risk Score + Confidence
      ↓
Decision
      ↓
Attack Paths
```

## What the tests verify

- Expected finding counts are produced from each fixture.
- Scanner metadata survives normalization.
- Scores remain within the CTM 0–100 range.
- Likelihood and impact remain within 0–10.
- Confidence remains within 0–1.
- Decisions use the supported CTM decision vocabulary.
- STRIDE, MITRE, and attack-path structures are produced.
- The high-risk Nuclei example retains its exposure and exploit context and maps to `T1190`.
- Empty exports do not create phantom findings.

## Security boundary

The fixtures are synthetic and non-production. These tests validate data processing and prioritization logic; they do not execute exploits or establish real-world exploitability.
