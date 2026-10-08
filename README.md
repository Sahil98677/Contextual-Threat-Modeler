# CTM Scanner Pipeline — Phase 3.1 Update

CTM consumes scanner and reconnaissance exports and converts them into context-aware security decisions. Scanner adapters do not launch scans or exploit targets.

## Supported scanner adapters

| Scanner | Export | Adapter key |
|---|---|---|
| Generic JSON | JSON | `generic-json` |
| Nmap | XML | `nmap` |
| Nuclei | JSONL | `nuclei` |
| Trivy | JSON | `trivy` |
| Qualys | XML | `qualys-xml` |
| Qualys | CSV | `qualys-csv` |
| Nessus | `.nessus` XML | `nessus` |

## Unified processing flow

```text
Scanner Export
      ↓
Adapter Registry
      ↓
Neutral Scanner Records
      ↓
CTM Normalization
      ↓
Asset / Finding Context
      ↓
STRIDE + MITRE Enrichment
      ↓
Risk Scoring
      ↓
Decision Engine
      ↓
Attack Paths
      ↓
Reporting
```

## Phase 3 validation fixtures

Synthetic fixtures are stored under `mock_inputs/scanner_samples/` for Nuclei, Trivy, Nessus, and Qualys CSV. They contain no real customer infrastructure or credentials.

## Phase 3.1 regression coverage

`tests/test_scanner_fixtures_e2e.py` exercises each fixture through `ctm.scanner_engine.run_scanner()` and verifies normalization, scoring, decisions, threat metadata, attack paths, scanner-specific fields, and empty-export behavior.

Run the complete test suite with:

```bash
pytest
```

## Safety boundary

CTM is an analysis and prioritization engine. It does not automatically exploit targets, bypass authentication, execute destructive payloads, or launch scanner jobs.
