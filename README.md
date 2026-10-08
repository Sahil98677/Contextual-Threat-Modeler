# Contextual Threat Modeler (CTM)

> A context-aware security decision engine that transforms vulnerability, reconnaissance, and scanner findings into prioritized security decisions.

CTM does not replace vulnerability scanners.

Instead, it consumes their results, adds business and security context, maps threats and attack techniques, calculates contextual risk, analyzes candidate attack paths, and determines what should be investigated or tested first.

---

## Why CTM?

Traditional scanners tell you:

> "This vulnerability exists."

CTM asks:

> "How dangerous is this vulnerability in this environment, how confident are we, what security controls exist, and what should we do about it?"

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
- Conservative attack-path correlation
- Automated security decisions
- Console, JSON, and HTML reporting
- Historical risk snapshots and posture trends
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
                Candidate Attack Paths
                           │
                           ▼
                Historical Risk Trend
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

| Scanner | Export | Adapter |
|---|---|---|
| Generic JSON | JSON | `generic-json` |
| Nmap | XML | `nmap` |
| Nuclei | JSONL | `nuclei` |
| Trivy | JSON | `trivy` |
| Qualys | XML | `qualys-xml` |
| Qualys | CSV | `qualys-csv` |
| Nessus | `.nessus` XML | `nessus` |

CTM consumes scanner output. It does **not** launch scanners or automatically exploit targets.

---

## CLI

Run the built-in CTM workflow:

```bash
ctm
```

Analyze an existing scanner export:

```bash
ctm --scanner nuclei --export nuclei_results.jsonl
```

Generate JSON or HTML:

```bash
ctm --scanner nuclei --export nuclei_results.jsonl --format json --output report.json
ctm --scanner nuclei --export nuclei_results.jsonl --format html --output report.html
```

Persist and compare historical risk:

```bash
ctm --history-dir .ctm-history
```

On the first run CTM establishes a `BASELINE`. Later runs report `IMPROVING`, `STABLE`, or `DEGRADING` based on the average contextual risk score, with per-asset deltas.

Historical snapshots are stored as dedicated `snapshot-*.json` files so unrelated JSON reports can safely coexist in the same directory.

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
- Attack-path correlation tests
- Historical trend tests
- CLI regression tests
- CI validation

Synthetic fixtures are used for pipeline validation and do not represent real customer infrastructure or credentials.

---

## Current Status

### Completed

- Core CTM risk engine
- Context engine
- STRIDE enrichment
- MITRE ATT&CK enrichment
- Decision engine
- Scanner adapter framework
- Generic JSON, Nmap, Nuclei, Trivy, Qualys XML, Qualys CSV, and Nessus adapters
- Scanner normalization and validation
- End-to-end scanner testing
- Analyst-oriented CLI
- JSON and self-contained HTML reporting
- Conservative same-asset attack-path correlation
- Scanner-engine attack-path parity
- Historical risk snapshots and trend comparison
- CI test matrix for Python 3.10, 3.11, and 3.12

### Roadmap

- API interface
- Web-based CTM dashboard
- Additional threat-intelligence enrichment
- Expanded historical analytics

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
- Attack-path correlation
- Risk trend analysis
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
