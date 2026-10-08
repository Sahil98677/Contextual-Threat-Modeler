## Phase 6.1 — Risk Trend Hardening and Repository Cleanup

Status: Prepared for upload — pending CI verification

### Changes
- Restricted historical snapshot loading to dedicated `snapshot-*.json` files
- Prevented unrelated JSON reports from being interpreted as CTM snapshots
- Added malformed-snapshot resilience
- Added regression coverage for history-directory edge cases
- Added `.gitignore` for Python artifacts, test output, virtual environments, and local CTM history
- Updated README current status, CLI usage, and Phase 6 documentation
- Added Phase 6.1 hardening documentation

### Cleanup required during upload
- Delete the duplicate root-level `PHASE6_RISK_TRENDS.md`
- Delete tracked `__pycache__/` and `*.pyc` artifacts

### Design boundary
This phase only hardens historical analysis and repository hygiene. It does not add a database, telemetry, continuous scanning, or automatic exploitation.

## Phase 6 — Risk Trend and Historical Intelligence

Status: Prepared for upload — pending CI verification

### Purpose
Give CTM a lightweight historical view of security posture so analysts can see whether contextual risk is improving, stable, or degrading between runs.

### Changes
- Added deterministic risk snapshots grouped by asset
- Added historical snapshot persistence as local JSON files
- Added current-versus-previous risk comparison
- Added overall posture states: `IMPROVING`, `STABLE`, `DEGRADING`, and `BASELINE`
- Added per-asset trend states and score deltas
- Added optional CLI `--history-dir` support
- Added trend information to console and JSON reporting
- Added regression coverage for snapshot aggregation, persistence, baseline, improvement, and degradation

### Design boundary
Phase 6 is historical analysis, not a database or continuous monitoring service. CTM records the results it already calculates; it does not collect telemetry or silently execute scans.
