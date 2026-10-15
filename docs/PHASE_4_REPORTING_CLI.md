# Phase 4 — Analyst-Oriented Reporting and CLI

## Purpose

Phase 4 makes CTM easier to use from the command line while keeping the interface deliberately small. The CLI is an orchestration layer: it selects an input source and report format, then delegates contextual analysis to the existing CTM engine.

## CLI design principle

CTM should not become another scanner CLI with dozens of tuning flags. The normal analyst workflow is intentionally simple:

```text
Scanner export
      ↓
    CTM CLI
      ↓
Decision Engine
      ↓
Console / JSON / HTML / SARIF
```

### Primary commands

Run the built-in CTM input set:

```bash
ctm
```

Analyze a scanner export:

```bash
ctm --scanner nuclei --export nuclei_results.jsonl
```

Write schema-validated JSON:

```bash
ctm --scanner nuclei --export nuclei_results.jsonl --format json --output report.json
```

Write HTML:

```bash
ctm --scanner nuclei --export nuclei_results.jsonl --format html --output report.html
```

Write SARIF 2.1.0 for code-scanning integrations:

```bash
ctm --scanner nuclei --export nuclei_results.jsonl --format sarif --output report.sarif
```

Supported scanner identifiers:

- `generic-json`
- `nmap`
- `nuclei`
- `trivy`
- `qualys-xml`
- `qualys-csv`
- `nessus`

## Reporting

### Console

The default format remains optimized for rapid analyst review. It shows contextual risk, decision, likelihood, impact, confidence, threat enrichment, ATT&CK mappings, attack-path count, and rationale.

### JSON

JSON now contains a small report envelope with:

- product name
- report type
- finding count
- risk/decision summary
- complete finding records
- a priority-ordered remediation plan

The generated payload is validated against CTM's JSON Schema before it is
returned. Validation failures are surfaced to the caller. This makes the output
easier for CI/CD and downstream integrations to consume without changing the
underlying finding model.

### SARIF

SARIF output uses version 2.1.0 and includes finding locations, risk-derived
result levels, rule identifiers (CWE identifiers when present), CTM scores,
decisions, priorities, remediation guidance, and contextual rationale. The
output is validated against the supported CTM SARIF contract. Locations refer
to finding endpoint paths; they are not source-code locations unless a scanner
supplied such a path.

### Remediation guidance

Console, HTML, JSON, and SARIF reports share decision-derived priorities: P1
for immediate testing, P2 for prioritized validation, P3 for investigation,
and P4 for monitoring. CWE-specific suggestions are qualified as conditional
on confirmation; they do not claim exploitability. Priorities are workflow
guidance and do not add risk-score weights.

### HTML

The HTML report is self-contained and suitable for opening locally or attaching to an assessment. It provides summary metrics, risk distribution, decision distribution, and finding-level contextual details.

## Input boundary

The CLI accepts existing scanner exports through the adapter layer. It does not launch Nmap, Nuclei, Nessus, Qualys, or other scanning tools. CTM remains an analysis and prioritization engine.

## Security boundary

The CLI does not automatically exploit targets, bypass authentication, or perform destructive actions. Any validation or penetration testing remains explicitly analyst-controlled.

## Validation

Reporting tests cover JSON schema validation, SARIF output and CLI file writing,
HTML/console recommendations, empty reports, scanner-source selection, and
invalid CLI combinations.
