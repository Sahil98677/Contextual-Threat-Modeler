## Phase 4.1 — Reporting Test Fixture Fix

Status: Prepared for upload

### Purpose
Fix the Phase 4 reporting regression tests so they provide the `sample_results` pytest fixture required by the JSON and HTML report tests.

### Changes
- Added a local `sample_results` pytest fixture backed by the deterministic `mock_inputs` dataset
- Kept reporting assertions unchanged
- Avoided introducing new CLI flags or changing CTM engine behavior

### CI validation
The failed CI run showed two reporting tests erroring during setup because `sample_results` was undefined. This update addresses that test-isolation issue directly.
