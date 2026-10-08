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

### CI validation
The failed CI run showed two reporting tests erroring during setup because `sample_results` was undefined. This update addresses that test-isolation issue directly.

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

### Design boundary
The CLI orchestrates input and reporting. Contextual risk calculation, threat modeling, scoring, decisions, and attack paths remain in the CTM engine.
