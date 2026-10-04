# Contextual Threat Modeler (CTM)

**CTM is a context-aware security decision engine for contextual threat modeling, risk scoring, attack-path analysis, and security prioritization.**

CTM is **not a vulnerability scanner**. It consumes findings from scanners/recon tools and answers:

> **"Given the vulnerability, the asset, exposure, controls, evidence, and confidence, what should security do next?"**

## Architecture

```text
Scanner / Recon Output
        |
        v
Input Normalizer
        |
        v
Context Engine
(Asset / Exposure / Controls)
        |
        v
Threat Modeling
(STRIDE + MITRE ATT&CK)
        |
        v
Attack Path Analysis
        |
        v
Risk Engine
(Likelihood / Impact / Confidence / Controls)
        |
        v
Decision Engine
        |
        +--> TEST_IMMEDIATELY
        +--> PRIORITIZE_VALIDATION
        +--> INVESTIGATE
        +--> MONITOR
        |
        v
JSON / Console Report
```

## What CTM considers

- Asset criticality
- Data classification
- Internet exposure
- Authentication requirements
- Trust zone
- Vulnerability status and confidence
- Exploit availability
- Attack complexity
- Secret exposure
- Existing security controls
- STRIDE threats
- MITRE ATT&CK techniques
- Attack paths and path impact

## Project structure

```text
Contextual-Threat-Modeler/
├── README.md
├── LICENSE
├── .gitignore
├── pyproject.toml
├── ctm_cli.py
├── ctm/
│   ├── __init__.py
│   ├── models.py
│   ├── ingestion.py
│   ├── engine.py
│   ├── context/
│   │   ├── __init__.py
│   │   ├── asset.py
│   │   ├── exposure.py
│   │   └── controls.py
│   ├── threat/
│   │   ├── __init__.py
│   │   ├── stride.py
│   │   ├── mitre.py
│   │   └── attack_paths.py
│   ├── scoring/
│   │   ├── __init__.py
│   │   ├── likelihood.py
│   │   ├── impact.py
│   │   ├── confidence.py
│   │   └── risk.py
│   ├── decision/
│   │   ├── __init__.py
│   │   └── decision_engine.py
│   └── reporting/
│       ├── __init__.py
│       ├── console.py
│       ├── json_report.py
│       └── html_report.py
├── adapters/
│   ├── __init__.py
│   ├── generic_json.py
│   ├── nmap.py
│   └── nuclei.py
├── mock_inputs/
│   ├── assets.json
│   ├── endpoints.json
│   ├── vulnerabilities.json
│   ├── controls.json
│   ├── header_data.json
│   └── secrets.json
├── tests/
│   ├── test_context.py
│   ├── test_scoring.py
│   ├── test_decision.py
│   ├── test_attack_paths.py
│   └── test_engine.py
└── docs/
    ├── architecture.md
    ├── risk-model.md
    └── threat-model.md
```

## Quick start

Requires Python 3.10+.

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install the project:

```bash
pip install -e .
```

Run CTM:

```bash
python ctm_cli.py --input-dir mock_inputs
```

JSON output:

```bash
python ctm_cli.py --input-dir mock_inputs --format json
```

HTML report:

```bash
python ctm_cli.py --input-dir mock_inputs --format html --output report.html
```

Run tests:

```bash
pytest
```

## Input model

The mock input directory contains six JSON files:

- `assets.json` — business/security context for assets
- `endpoints.json` — discovered endpoints
- `vulnerabilities.json` — vulnerability evidence
- `controls.json` — compensating controls
- `header_data.json` — HTTP security-header context
- `secrets.json` — potential secret exposure

CTM intentionally separates **discovery** from **validation**. A scanner finding does not automatically become a confirmed vulnerability.

## Decision semantics

| Risk score | Confidence | Decision |
|---:|---:|---|
| 85–100 | ≥ 60% | TEST_IMMEDIATELY |
| 70–84.9 | any | PRIORITIZE_VALIDATION |
| 45–69.9 | any | INVESTIGATE |
| < 45 | any | MONITOR |

These thresholds are deliberately simple and configurable in code. They are a prioritization model, not a replacement for organizational risk policy.

## Safety boundary

CTM performs **analysis and prioritization**. It does not automatically exploit targets, execute payloads, bypass authentication, or perform destructive actions.

Scanner adapters normalize data; they do not launch scans.

## Roadmap

- [x] Context-aware finding model
- [x] STRIDE mapping
- [x] MITRE ATT&CK mapping
- [x] Confidence-aware risk scoring
- [x] Control-aware scoring
- [x] Attack-path reasoning
- [x] Generic JSON adapter
- [x] Nmap XML adapter
- [x] Nuclei JSONL adapter
- [x] Console / JSON / HTML reporting
- [x] Automated tests
- [ ] Plugin architecture for additional scanners
- [ ] Configurable scoring policies
- [ ] Graph database backend for large attack-path datasets
- [ ] API service

## License

MIT
