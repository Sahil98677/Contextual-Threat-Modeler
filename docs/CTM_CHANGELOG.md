## Phase 5 — Attack-Path Correlation

Status: Prepared for upload

### Purpose
Improve CTM attack-path analysis so related findings can be presented as conservative candidate attack paths rather than isolated one-finding paths.

### Changes
- Added path IDs, nodes, finding IDs, and correlation metadata to attack paths
- Added same-asset candidate correlation across findings
- Added path-level scoring and prioritization
- Added attack-path display to console reporting
- Added attack-path flow cards to HTML reporting
- Preserved full attack-path structures in JSON reporting through existing finding serialization
- Kept correlation conservative and explicitly distinguished from verified exploit chains
- Added Phase 5 attack-path documentation and regression coverage

### Design boundary
Attack-path correlation is an analysis and prioritization capability. CTM does not automatically exploit targets or claim exploitability relationships that are not supported by input context.
