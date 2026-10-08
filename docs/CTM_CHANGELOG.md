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

## Phase 5.1 — Scanner Engine Attack-Path Parity

Status: Completed — CI verification pending

### Purpose
Ensure scanner-export analysis uses the same conservative attack-path correlation model as the built-in CTM input workflow.

### Changes
- Replaced per-finding scanner-engine path construction with the Phase 5 correlation engine
- Correlate same-asset scanner findings when at least one finding is internet-facing
- Attach correlated path structures back to every participating finding
- Added scanner-engine regression coverage for same-asset correlation
- Preserved the existing scanner adapter and risk-scoring boundaries

### Design boundary
Scanner exports are normalized into CTM findings before analysis. Correlation remains conservative candidate analysis and does not claim exploitability between findings unless the input context establishes that relationship.

## Phase 5 — Attack-Path Correlation

Status: Implemented — pending CI verification

### Purpose
Improve CTM attack-path analysis so related findings can be presented as conservative candidate attack paths rather than isolated one-finding paths.

### Changes
- Added path IDs, nodes, finding IDs, and correlation metadata to attack paths
- Added same-asset candidate correlation across findings
- Added path-level scoring and prioritization
- Added attack-path display to console reporting
- Added attack-path flow cards to HTML reporting
- Preserved full attack-path structures in JSON reporting through existing finding serialization
- Added regression coverage for same-asset correlation and internal-only findings
- Kept correlation conservative and explicitly distinguished from verified exploit chains

### Design boundary
Attack-path correlation is an analysis and prioritization capability. CTM does not automatically exploit targets or claim exploitability relationships that are not supported by input context.

## Phase 4.1 — Reporting Test Fixture Fix

Status: Completed

### Purpose
Fix the Phase 4 reporting regression tests so they provide the `sample_results` pytest fixture required by the JSON and HTML report tests.

### Changes
- Added a local `sample_results` pytest fixture backed by the deterministic `mock_inputs` dataset
- Kept reporting assertions unchanged
- Avoided introducing new CLI flags or changing CTM engine behavior

## Phase 4 — Analyst-Oriented Reporting and CLI

Status: Completed

### Purpose
Keep the CLI clean and analyst-oriented rather than turning CTM into another scanner CLI with dozens of flags.

### Changes
- Added direct scanner-export input through `--scanner` and `--export`
- Kept the primary interface to a small set of source, format, and output options
- Preserved the existing `ctm` default workflow for built-in CTM inputs
- Added structured JSON report metadata and summary information
- Improved self-contained HTML reporting with summary metrics and finding details
- Added regression tests for reporting and CLI validation
- Added phase-specific usage and security-boundary documentation
