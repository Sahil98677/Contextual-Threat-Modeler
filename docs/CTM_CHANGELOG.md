# CTM Development Changelog

This file records meaningful architecture and implementation updates so project documentation can be reconstructed from the repository itself.

## Phase 3.1 — End-to-End Scanner Validation

Status: Uploaded

### Purpose
Strengthen Phase 3 by testing all synthetic scanner fixtures through the complete scanner-to-CTM pipeline.

### Added
- End-to-end regression tests for Nuclei, Trivy, Nessus, and Qualys CSV
- Scanner-specific metadata preservation checks
- Risk, confidence, decision, STRIDE, MITRE, and attack-path assertions
- Empty-export regression tests for all four scanner formats
- README scanner-pipeline documentation updates

### Scoring and MITRE context fixes
The Nuclei high-risk fixture explicitly represents an API endpoint with criticality 5 and restricted data classification. The explicit `endpoint_type: api` is required because the existing MITRE mapper maps `api` endpoints to `T1190 - Exploit Public-Facing Application`; a generic `https` service alone does not trigger that mapping.

The fixture therefore tests both contextual risk prioritization and the intended MITRE enrichment path without changing production engine behavior.

### CI validation
The previous CI failure was traced to fixture context: the endpoint was normalized as `https`, so the existing MITRE mapping correctly returned an empty list. The fixture now declares its semantic endpoint type as `api`.

### Validation boundary
Tests verify parsing, normalization, contextual enrichment, scoring, decisions, and attack-path generation. They do not claim synthetic findings are exploitable in real environments.

---

## Phase 3 — Scanner Validation and Reporting

Status: Uploaded

### Purpose
Validate the complete scanner-to-CTM path using safe synthetic exports and add a compact reporting summary.

### Added
- Synthetic Nuclei JSONL fixture
- Synthetic Trivy JSON fixture
- Synthetic Nessus XML fixture
- Synthetic Qualys CSV fixture
- `ctm/scanner_validation.py`
- `tests/test_scanner_validation.py`
- `docs/PHASE_3_VALIDATION_REPORTING.md`

### Validation path
Scanner export → Adapter → Normalization → Finding/Asset → STRIDE + MITRE → Risk → Decision → Attack Paths → Summary.

### Security considerations
Fixtures contain synthetic data only. No real credentials, customer infrastructure, or production scan exports should be committed.

---

## Phase 2.1 — Scanner Normalization Hardening

Status: Uploaded

### Changes
- Safe boolean parsing
- Criticality normalization to 1–5
- Severity normalization
- Explicit status precedence
- Deterministic sanitized asset IDs
- Type checks for controls and tags
- Boolean normalization for exploit availability

### Tests
Regression tests cover boolean handling, criticality, severity, status, asset IDs, and invalid types.

---

## Phase 2 — Unified Scanner Pipeline

Status: Uploaded

### Added
- `ctm/scanner_engine.py`
- `tests/test_scanner_engine.py`
- `docs/PHASE_2_SCANNER_PIPELINE.md`

### Pipeline
Scanner export → Adapter Registry → Neutral Records → CTM Normalization → Asset/Finding → STRIDE + MITRE → Risk → Decision → Attack Paths.

### Supported scanners
Generic JSON, Nmap, Nuclei, Trivy, Qualys XML, Qualys CSV, Nessus.

---

## Phase 1.1 — Adapter Contract

Status: Uploaded

### Added/updated
- `adapters/base.py`
- `adapters/generic_json.py`
- `adapters/nmap.py`
- `adapters/nuclei.py`
- `adapters/trivy.py`
- `adapters/qualys.py`
- `adapters/nessus.py`
- `adapters/registry.py`
- `tests/test_adapters.py`

### Architecture
All scanner adapters implement the common `ScannerAdapter` interface and are resolved through the adapter registry.

---

## Initial CTM Foundation

The project established:
- Asset and Finding models
- input validation and normalization
- context-aware risk scoring
- control modifiers
- confidence scoring
- decision engine
- STRIDE enrichment
- MITRE ATT&CK enrichment
- attack-path analysis
- reporting/CLI components
- scanner adapter architecture
