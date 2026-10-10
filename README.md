# Contextual Threat Modeler (CTM)

> A context-aware security decision engine that transforms vulnerability, reconnaissance, and scanner findings into prioritized security decisions.

CTM does not replace vulnerability scanners. It consumes their results, adds business and security context, maps threats and attack techniques, calculates contextual risk, analyzes candidate attack paths, and helps determine what should be investigated or tested first.

## Why CTM?

Traditional scanners tell you:

> "This vulnerability exists."

CTM asks:

> "How dangerous is this vulnerability in this environment, how confident are we, what security controls exist, and what should we do about it?"

```text
Scanner Finding
      ↓
Asset Criticality + Internet Exposure + Authentication Context
      + Data Classification + Vulnerability Evidence + Security Controls
      ↓
Contextual Risk Score → Security Decision → Candidate Attack Paths
```

## Core Capabilities

- Scanner and reconnaissance result ingestion
- Unified scanner adapter architecture
- Asset and exposure context
- Vulnerability normalization
- STRIDE threat mapping
- MITRE ATT&CK enrichment
- Context-aware likelihood and business-impact calculation
- Security-control adjustment and confidence scoring
- Risk prioritization and automated security decisions
- Conservative attack-path correlation
- Console, JSON, and HTML reporting
- Historical risk snapshots and posture trends
- Regression and end-to-end testing

---

## Getting Started

You can run CTM locally on **Windows, Linux, Kali Linux, or macOS** with **Python 3.10 or newer**. You can start with the synthetic sample data included in this repository; you do not need to install a scanner to try CTM.

### 1. Download the repository

**Option A — Git (recommended)**

```bash
git clone https://github.com/Sahil98677/Contextual-Threat-Modeler.git
cd Contextual-Threat-Modeler
```

**Option B — Download ZIP**

1. Open the [CTM GitHub repository](https://github.com/Sahil98677/Contextual-Threat-Modeler).
2. Select **Code → Download ZIP**.
3. Extract the ZIP file.
4. Open a terminal in the extracted `Contextual-Threat-Modeler` folder.

Run the remaining commands from the repository's root folder.

### 2. Check your Python version

```bash
python --version
```

The version must be Python 3.10 or newer. On Linux/macOS, you may need to use `python3 --version`.

### 3. Create a virtual environment

**Windows — PowerShell**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell prevents activation, use Command Prompt instead:

```bat
py -3 -m venv .venv
.venv\Scripts\activate.bat
```

**Linux, Kali Linux, or macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

If creating the virtual environment fails on Debian/Kali-based Linux, install the Python venv package appropriate for your Python version. For example:

```bash
sudo apt install python3-venv
```

### 4. Install CTM

With the virtual environment activated, run this from the repository root:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

### 5. Run CTM for the first time

```bash
ctm
```

This runs CTM against the sample input files in `mock_inputs/` and prints prioritized findings and security decisions in the terminal.

The included sample data is **synthetic demonstration data**. It does not represent real customer infrastructure, credentials, or scan results.

If your terminal cannot find the `ctm` command, try:

```bash
python ctm_cli.py
```

### 6. Generate reports

**Print JSON to the terminal**

```bash
ctm --format json
```

**Save a JSON report**

```bash
ctm --format json --output report.json
```

**Save an HTML report**

```bash
ctm --format html --output report.html
```

Open `report.html` in your browser to review the report.

### 7. Analyze an existing scanner export

CTM analyzes existing scanner output; **it does not launch scanners or automatically exploit targets**. Choose the adapter that matches the export file.

**Nuclei — JSONL export**

```bash
ctm --scanner nuclei --export path/to/nuclei_results.jsonl
```

**Trivy — JSON export**

```bash
ctm --scanner trivy --export path/to/trivy_results.json --format json --output trivy_report.json
```

**Nessus — `.nessus` XML export**

```bash
ctm --scanner nessus --export path/to/scan.nessus --format html --output nessus_report.html
```

Replace each example path with the location of your actual export file.

Supported adapters:

| Scanner / input | Expected export | Adapter name |
|---|---|---|
| Generic JSON | JSON | `generic-json` |
| Nmap | XML | `nmap` |
| Nuclei | JSONL | `nuclei` |
| Trivy | JSON | `trivy` |
| Qualys | XML | `qualys-xml` |
| Qualys | CSV | `qualys-csv` |
| Nessus | `.nessus` XML | `nessus` |

### 8. Compare risk over time

```bash
ctm --history-dir .ctm-history
```

The first run creates a baseline. Later runs compare new results with earlier snapshots. Reuse the same history directory across assessments to compare them.

### 9. Run the test suite

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

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
              │  Asset Criticality      │
              │  Exposure               │
              │  Authentication         │
              │  Data Classification    │
              │  Security Controls      │
              └────────────┬────────────┘
                           ▼
                 STRIDE + MITRE ATT&CK
                           ▼
                    Risk Calculation
                           ▼
                    Decision Engine
                           ▼
                Candidate Attack Paths
                           ▼
                Historical Risk Trends
                           ▼
                       Reporting
```

## Risk Model

CTM calculates contextual risk using:

**Risk = Likelihood × Impact × Control Modifier**

The resulting score is capped at 100.

Contextual factors include internet exposure, authentication requirements, DMZ placement, asset criticality, data classification, vulnerability severity, exploit availability, attack complexity, validation status, security controls, and secret exposure.

### Decision Model

| Risk Score | Decision |
|---:|---|
| ≥ 85 | `TEST_IMMEDIATELY` |
| ≥ 70 | `PRIORITIZE_VALIDATION` |
| ≥ 45 | `INVESTIGATE` |
| < 45 | `MONITOR` |

## Validation

The project includes unit tests, scanner adapter tests, normalization tests, risk-scoring tests, security-control tests, scanner fixture tests, end-to-end scanner pipeline tests, attack-path correlation tests, historical trend tests, CLI regression tests, and CI validation.

Synthetic fixtures are used for pipeline validation and do not represent real customer infrastructure or credentials.

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

## Documentation

Detailed documentation is maintained under `docs/`. Key documentation covers CTM architecture, the scanner pipeline, validation and reporting, hardening, attack-path correlation, risk trend analysis, and the project changelog.

Development milestones are tracked in `docs/CTM_CHANGELOG.md`.

- [Contributing to CTM](CONTRIBUTING.md) — development setup, testing, and pull request guidelines.

## Troubleshooting

- **`ctm` is not recognized / command not found:** Activate the virtual environment and install the project with `python -m pip install -e .`. You can also try `python ctm_cli.py` from the repository root.
- **Python version error:** Install and select Python 3.10 or newer.
- **Missing input files:** Run the built-in workflow from the repository root so the `mock_inputs/` directory can be found. To use a different input directory, pass `--input-dir path/to/input_directory`.
- **Scanner export error:** Confirm that the export file exists and matches the selected adapter's expected format.
- **Virtual environment creation fails:** On Debian/Kali-based systems, install the matching `python3-venv` package.

## Security Boundary

CTM is an **analysis and prioritization engine**. It does not automatically exploit targets, bypass authentication, execute destructive payloads, or launch vulnerability scanners. Scanner exports and reconnaissance data are inputs to the decision engine.

Only analyze systems and data you are authorized to assess.

## License

MIT
