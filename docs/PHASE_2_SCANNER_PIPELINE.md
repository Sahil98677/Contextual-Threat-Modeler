# CTM Phase 2 — Unified Scanner Pipeline

Phase 2 connects the scanner adapter layer to the existing CTM decision engine.

## Flow

Scanner export → adapter registry → neutral scanner records → CTM normalization → Asset/Finding models → STRIDE + MITRE → risk scoring → decision → attack paths.

## API

```python
from ctm.scanner_engine import run_scanner

results = run_scanner("nuclei", "results.jsonl")
```

For JSON-ready output:

```python
from ctm.scanner_engine import run_scanner_dicts

results = run_scanner_dicts("nessus", "scan.nessus")
```

Supported scanner names:

- `generic-json`
- `nmap`
- `nuclei`
- `trivy`
- `qualys-xml`
- `qualys-csv`
- `nessus`

## Important Nmap boundary

Nmap primarily discovers exposed services and ports; an open port is not automatically a vulnerability. The current Phase 2 path can process Nmap records for end-to-end integration testing, but production policy should distinguish **service inventory** from **security findings** before assigning remediation priority.

## Security boundary

The adapters only parse existing export files. They do not execute Nmap, Nuclei, Trivy, Qualys, or Nessus scans.
