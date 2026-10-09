## Phase 6.4 — Scanner Reliability and Input Hardening

**Status:** Prepared patch — pending upload and CI validation.

- Fixed scanner severity normalization for Nessus (0–4) and Qualys (1–5).
- Added fallback use of Nessus `risk_factor` when severity is missing or unknown.
- Preserved optional scanner-supplied asset and exposure context.
- Reused the shared boolean normalization helper.
- Replaced Nessus and Qualys XML parsing with `defusedxml`.
- Centralized risk thresholds for decisions, trends, and scanner summaries.
- Added severity and XML hardening regression tests.
- Added Ruff, Bandit, and scoped mypy checks to CI.

**Note:** This entry is a prepared changelog snippet. Append it to `docs/CTM_CHANGELOG.md`
only after the patch is uploaded, reviewed, and CI passes. Do not replace the existing changelog.
