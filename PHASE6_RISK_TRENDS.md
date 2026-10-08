# Phase 6 — Risk Trend & Historical Intelligence

Phase 6 adds lightweight historical posture tracking without introducing a database or background monitoring service.

## Usage

Run CTM normally:

```bash
ctm
```

Persist the run and compare it with the previous run:

```bash
ctm --history-dir .ctm-history
```

With scanner exports:

```bash
ctm --scanner nuclei --export nuclei_results.jsonl --history-dir .ctm-history
```

JSON output can include the trend comparison:

```bash
ctm --history-dir .ctm-history --format json --output report.json
```

## Snapshot model

Each snapshot records:

- timestamp
- finding count
- average risk score
- highest risk score
- risk bucket counts
- per-asset maximum and average score
- per-asset risk bucket counts

Snapshots are stored as local JSON files under the directory supplied to `--history-dir`.

## Trend semantics

CTM compares the current average risk score with the previous snapshot:

- `IMPROVING` — average score decreased
- `DEGRADING` — average score increased
- `STABLE` — no meaningful change
- `BASELINE` — no previous snapshot exists

Per-asset comparison uses the same rule against the asset's maximum finding score.

## Security boundary

Historical intelligence only analyzes findings CTM has already processed. It does not launch scans, collect telemetry, or infer exploitability from a trend alone.
