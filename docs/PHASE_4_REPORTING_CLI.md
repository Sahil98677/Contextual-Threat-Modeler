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
Console / JSON / HTML
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

Write JSON:

```bash
ctm --scanner nuclei --export nuclei_results.jsonl --format json --output report.json
```

Write HTML:

```bash
ctm --scanner nuclei --export nuclei_results.jsonl --format html --output report.html
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

This makes the output easier for CI/CD, automation, and downstream integrations to consume without changing the underlying finding model.

### HTML

The HTML report is self-contained and suitable for opening locally or attaching to an assessment. It provides summary metrics, risk distribution, decision distribution, and finding-level contextual details.

## Input boundary

The CLI accepts existing scanner exports through the adapter layer. It does not launch Nmap, Nuclei, Nessus, Qualys, or other scanning tools. CTM remains an analysis and prioritization engine.

## Security boundary

The CLI does not automatically exploit targets, bypass authentication, or perform destructive actions. Any validation or penetration testing remains explicitly analyst-controlled.

## Validation

Phase 4 adds regression coverage for JSON/HTML reporting, empty reports, scanner-source selection, and invalid CLI combinations.
