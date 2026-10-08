# Contextual Threat Modeler (CTM)

> A context-aware security decision engine that transforms vulnerability, reconnaissance, and scanner findings into prioritized security decisions.

CTM does not replace vulnerability scanners.

Instead, it consumes their results, adds business and security context, maps threats and attack techniques, calculates contextual risk, analyzes attack paths, and determines what should be investigated or tested first.

---

## Why CTM?

Traditional scanners tell you:

> "This vulnerability exists."

CTM asks:

> "How dangerous is this vulnerability in this environment, how confident are we, what security controls exist, and what should we do about it?"

Example:

```text
Scanner Finding
      ↓
Asset Criticality
      +
Internet Exposure
      +
Authentication Context
      +
Data Classification
      +
Vulnerability Evidence
      +
Security Controls
      ↓
Contextual Risk Score
      ↓
Security Decision
```

---

## Core Capabilities

- Scanner and reconnaissance result ingestion
- Unified scanner adapter architecture
- Asset and exposure context
- Vulnerability normalization
- STRIDE threat mapping
- MITRE ATT&CK enrichment
- Context-aware likelihood calculation
- Business-impact calculation
- Security-control adjustment
- Confidence scoring
- Risk prioritization
- Attack-path generation
- Automated security decisions
- Reporting support
- Regression and end-to-end testing

---

## Architecture

```text
                    Scanner / Recon Data
                            │
                            ▼
                    Scanner Adapters
                            │
                            ▼
                 Neutral Scanner Records
                            │
                            ▼
                      Normalization
                            │
                            ▼
              ┌─────────────────────────┐
              │      Security Context   │
              │                         │
              │  Asset Criticality      │
              │  Exposure               │
              │  Authentication         │
              │  Data Classification    │
              │  Security Controls      │
              └────────────┬────────────┘
                           │
                           ▼
                 STRIDE + MITRE ATT&CK
                           │
                           ▼
                  Risk Calculation
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
        Likelihood                    Impact
              │                         │
              └────────────┬────────────┘
                           ▼
                   Control Modifier
                           │
                           ▼
                    Risk Score
                           │
                           ▼
                   Decision Engine
                           │
                           ▼
                   Attack Paths
                           │
                           ▼
                      Reporting
```

---

## Risk Model

CTM currently calculates:

**Risk = Likelihood × Impact × Control Modifier**

The resulting score is capped at 100.

Contextual factors include:

- Internet exposure
- Authentication requirements
- DMZ placement
- Asset criticality
- Data classification
- Vulnerability severity
- Exploit availability
- Attack complexity
- Validation status
- Security controls
- Secret exposure

### Decision Model

| Risk Score | Decision |
|---:|---|
| ≥ 85 | `TEST_IMMEDIATELY` |
| ≥ 70 | `PRIORITIZE_VALIDATION` |
| ≥ 45 | `INVESTIGATE` |
| < 45 | `MONITOR` |

---

## Supported Scanner Adapters

CTM currently supports:

| Scanner | Export | Adapter |
|---|---|---|
| Generic JSON | JSON | `generic-json` |
| Nmap | XML | `nmap` |
| Nuclei | JSONL | `nuclei` |
| Trivy | JSON | `trivy` |
| Qualys | XML | `qualys-xml` |
| Qualys | CSV | `qualys-csv` |
| Nessus | `.nessus` XML | `nessus` |

### Scanner Integration Flow

```text
Scanner Export
      ↓
Adapter
      ↓
Normalized Record
      ↓
CTM Finding
      ↓
Context Enrichment
      ↓
Risk + Threat Analysis
      ↓
Security Decision
```

CTM consumes scanner output.

It does **not** launch scanners or automatically exploit targets.

---

## Example

A scanner may report:

```text
Critical API vulnerability
```

CTM can combine that finding with:

```text
Internet-facing       → Yes
Authentication        → Not required
Asset criticality     → 5/5
Data classification   → Restricted
Exploit available     → Yes
Attack complexity     → Low
Validation status     → Confirmed
```

Result:

```text
Risk Score:     100
Confidence:     95%
Risk Level:     CRITICAL
Decision:       TEST_IMMEDIATELY
```

This is the core idea behind CTM:

> **The same vulnerability can have very different risk depending on context.**

---

## Project Structure

```text
Contextual-Threat-Modeler/
│
├── ctm/
│   ├── context/
│   ├── decision/
│   ├── reporting/
│   ├── scoring/
│   ├── threat/
│   ├── engine.py
│   ├── scanner.py
│   ├── scanner_engine.py
│   └── scanner_validation.py
│
├── adapters/
│   ├── generic_json.py
│   ├── nmap.py
│   ├── nuclei.py
│   ├── trivy.py
│   ├── qualys.py
│   ├── nessus.py
│   └── registry.py
│
├── mock_inputs/
│   └── scanner_samples/
│
├── tests/
│
├── docs/
│
└── README.md
```

---

## Validation

The project includes:

- Unit tests
- Scanner adapter tests
- Normalization tests
- Risk-scoring tests
- Security-control tests
- Scanner fixture tests
- End-to-end scanner pipeline tests
- Empty-export regression tests

The scanner pipeline has been validated against synthetic:

- Nuclei
- Trivy
- Nessus
- Qualys CSV

CI tests:

```text
Python 3.10 ✓
Python 3.11 ✓
Python 3.12 ✓
```

Synthetic fixtures are used for pipeline validation and do not represent real customer infrastructure or credentials.

---

## Current Status

### Completed

- Core CTM risk engine
- Context engine
- STRIDE enrichment
- MITRE ATT&CK enrichment
- Decision engine
- Attack-path analysis
- Scanner adapter framework
- Generic JSON adapter
- Nmap adapter
- Nuclei adapter
- Trivy adapter
- Qualys XML adapter
- Qualys CSV adapter
- Nessus adapter
- Scanner normalization
- Scanner validation
- End-to-end scanner testing
- CI validation

### Roadmap

- Advanced reporting
- HTML security reports
- Additional scanner integrations
- Improved attack-path correlation
- Risk trend analysis
- API interface
- Web-based CTM dashboard
- Additional threat-intelligence enrichment

---

## Documentation

Detailed documentation is maintained under:

```text
docs/
```

Key documentation includes:

- CTM architecture
- Scanner pipeline
- Validation and reporting
- Hardening
- Changelog

The development history and milestone-level changes are tracked in `docs/CTM_CHANGELOG.md`.

---

## Security Boundary

CTM is designed as an **analysis and prioritization engine**.

It does not automatically:

- exploit targets
- bypass authentication
- execute destructive payloads
- launch vulnerability scanners
- attack third-party infrastructure

Scanner exports and reconnaissance data are treated as input to the decision engine.

---

## License

MIT
