# CTM Phase 3.1 — End-to-End Scanner Validation

Phase 3.1 turns the synthetic scanner fixtures from parsing examples into regression coverage for the complete CTM scanner pipeline.

## Covered scanners

- Nuclei JSONL
- Trivy JSON
- Nessus `.nessus` XML
- Qualys CSV

## Validation path

Synthetic Export → Scanner Adapter → Neutral Records → CTM Normalization → Asset/Finding → STRIDE + MITRE → Likelihood + Impact + Controls → Risk + Confidence → Decision → Attack Paths.

## Scoring-aligned high-risk fixture

The Nuclei `/api/users` fixture explicitly supplies a highly critical, restricted asset context so the test exercises the intended CTM scoring model. With internet exposure, no authentication, confirmed critical severity, exploit availability, and low attack complexity, the fixture reaches the `TEST_IMMEDIATELY` threshold.

The test validates the model rather than hard-coding an arbitrary score for an ordinary critical finding.

## Security boundary

The fixtures are synthetic and non-production. These tests validate data processing and prioritization logic; they do not execute exploits or establish real-world exploitability.
