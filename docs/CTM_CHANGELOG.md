
## Phase 4 — Analyst-Oriented Reporting and CLI

Status: Prepared for upload

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
