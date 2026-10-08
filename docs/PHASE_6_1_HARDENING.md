# Phase 6.1 — Risk Trend Hardening and Repository Cleanup

## Purpose

Harden the Phase 6 historical-risk implementation and clean generated artifacts from the repository before the next major phase.

## Changes

- Restrict historical snapshot discovery to `snapshot-*.json`.
- Ignore malformed or unrelated JSON files in the history directory.
- Add regression coverage for unrelated JSON and malformed snapshots.
- Add a repository `.gitignore` covering Python build/test artifacts and local CTM history.
- Keep historical snapshots separate from report output files.
- Update README documentation to reflect completed Phase 6 functionality and current CLI usage.

## Design boundary

Phase 6.1 does not introduce a database, telemetry collection, continuous scanning, or automatic exploitation. It only hardens the historical analysis already performed by CTM.
