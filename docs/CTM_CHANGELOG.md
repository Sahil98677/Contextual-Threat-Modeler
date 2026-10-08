# CTM Development Changelog

This file records meaningful architecture and implementation updates so project documentation can be reconstructed from the repository itself.

## Phase 2.1 — Scanner Normalization Hardening

Status: Prepared for upload

### Purpose
Harden the boundary between external scanner exports and CTM's internal data model.

### Changes
- Added safe boolean parsing for external scanner values.
- Prevented values such as `"false"` from becoming Python `True`.
- Normalized asset criticality to the CTM 1–5 range.
- Added fallback to criticality 3 for malformed values.
- Normalized scanner severity to CTM severity categories.
- Preserved explicit vulnerability status when supplied.
- Added deterministic sanitized scanner asset IDs.
- Added type checks for scanner-provided controls and tags.
- Normalized `exploit_available` to a real boolean.

### Tests
Added regression coverage for:
- string boolean handling
- criticality clamping
- malformed criticality
- severity normalization
- explicit status precedence
- deterministic asset IDs
- invalid controls/tags

### Architecture impact
The scanner ingestion boundary is now more defensive before data reaches:
`Finding → STRIDE → MITRE → Risk → Decision → Attack Paths`.

### Security impact
Scanner exports are treated as untrusted input and constrained before their values influence CTM scoring or decisions.

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

### Important boundary
Nmap service discovery is not automatically equivalent to a vulnerability finding.

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
All scanner adapters now implement the common `ScannerAdapter` interface and are resolved through the adapter registry.

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
