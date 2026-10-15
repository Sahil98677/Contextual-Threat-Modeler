# CTM Project Milestone Roadmap

Contextual Threat Modeler (CTM) is an open-source security analysis engine.
Its goal is to assess findings in context—including asset criticality,
exposure, authentication, data sensitivity, security controls, confidence,
attack paths, and business impact—and produce useful risk decisions.

This roadmap distinguishes implemented foundations from work that still needs
end-to-end assessment. Completed milestones do not by themselves establish
production readiness.

## Milestones

| Milestone | Area | Status |
|---|---|---|
| M0 | Core risk engine | Foundation implemented: asset and finding models, contextual scoring, confidence, likelihood, impact, rationale, and decisions. |
| M1 | Scanner adapters | Adapters implemented for generic JSON, Nmap, Nuclei, Trivy, Qualys XML/CSV, and Nessus. Complete adapter-to-risk-pipeline coverage is assessed under M7. |
| M2 | Finding provenance and confidence | Implemented: scanner-reported severity is distinct from validation status; scanner assertions are not independent verification. |
| M3 | Controlled verification | Implemented: CTM records review decisions and audit metadata. Reviewer authentication and authorization remain the responsibility of a trusted caller. |
| M4 | Tamper-evident audit trail | Implemented in commit `7b58a9c`: hash-chained review events, status transitions, tamper detection, and rejection of invalid existing history. Local tests and quality checks passed; confirm the corresponding GitHub Actions run before treating remote CI as verified. |
| M5 | Authenticated reviewer authorization | Authorization boundary implemented: verification requires a trusted authorizer, decision-specific permission checks, and authorizer-derived reviewer attribution. A deployment must still connect an authenticated identity provider and enforce its access policy. |
| M6 | Persistent audit storage | Implemented with a SQLite-backed audit store, transactionally appended hash-chained events, tamper checks, update/delete guards, and explicit recovery of finding status and provenance after restart. `tests/test_audit_storage.py` exercises SQLite write failures, corrupt records, sequence gaps, broken links, and open errors. Protect the database and its directory with deployment-level access controls. |
| M7 | Unified scanner ingestion | Implemented: all seven supported adapters are exercised through parsing, common normalization, threat enrichment, scoring, decisions, and reporting; regression tests cover safe synthetic fixtures and the repository's tagged vulnerability input. CWE metadata is preserved for downstream context and controls. Validate representative exports from each deployed scanner version before operational use. |
| M8 | Contextual risk calibration | Implemented without changing score weights: `docs/risk-model.md` documents the factors, assumptions, thresholds, and limits; deterministic tests cover factor ordering and boundaries. Risk rationale now uses the same boolean normalization as exposure scoring, preventing string booleans from producing contradictory explanations. These heuristic weights are not empirically calibrated against real-world outcomes. |
| M9 | STRIDE and MITRE ATT&CK mapping | Implemented with explicit inferred-candidate classification, rule-basis evidence, ATT&CK references, narrower evidence-gated technique candidates, unknown-endpoint handling, and deterministic mapping tests. Mappings do not change risk scores or assert confirmed threat/technique use. See `docs/threat-mapping.md`. |
| M10 | Attack-path analysis | Implemented conservatively: explicit internet-exposure evidence and shared asset IDs produce deterministic, unordered candidate correlations with score basis and limitations. Results are never marked confirmed; network reachability, exploit chains, and control bypass are not inferred. See `docs/PHASE_5_ATTACK_PATH_CORRELATION.md`. |
| M11 | Actionable decisions and reporting | Implemented: deterministic P1–P4 remediation plans, CWE-specific conditional guidance, concise rationale, validated JSON report payloads, SARIF 2.1.0 output, and analyst-facing console/HTML recommendations. Priorities do not alter risk scores or imply exploitability. See `docs/PHASE_4_REPORTING_CLI.md`. |
| M12 | Release hardening and adoption | Implemented: README, architecture, and threat-model guidance match shipped behavior and limitations; sample data is synthetic; CI tests Python 3.10–3.12 and builds source/wheel distributions, then installs the wheel in a clean environment and smoke-tests CLI/SARIF output. Local test, Ruff, Bandit, Mypy, and clean wheel-install checks passed. This is release preparation, not a production-readiness or external scanner-compatibility certification. |

## Recommended implementation order

The milestone numbers describe scope, not necessarily execution order. Work in
this dependency order:

1. **M5–M6 — Close verification trust and audit-storage gaps.**
2. **M7 — Verify that scanner exports reliably reach the risk engine.**
3. **M8 — Calibrate risk using reliable normalized inputs.**
4. **M9–M10 — Improve threat context and attack-chain reasoning.**
5. **M11 — Deliver actionable decisions and reporting.**
6. **M12 — Prepare for a reliable public release.**

M7 is covered with synthetic fixtures, but adapter availability and synthetic
fixtures do not guarantee compatibility with every scanner version or every
optional field. Validate representative real exports before operational use.

## Definition of done

Every milestone should meet these criteria before it is considered complete:

- Changes are small, reviewable, and covered by normal, edge, and negative-case
  tests.
- Ruff, Bandit, mypy, and the existing test suite pass.
- CI passes on supported Python versions, with the successful workflow run
  verified.
- Documentation describes the implemented behavior and its security
  limitations accurately.
- The work is committed and pushed; the relevant commit and CI status are
  checked before proceeding.

## Security and readiness boundaries

- A recorded reviewer ID is not proof of identity. A trusted authorizer must
  resolve the authenticated identity and authorize the requested action; the
  deployment must connect this interface to its identity provider and access
  policy.
- Hash chaining and SQLite update/delete guards make stored verification history
  tamper-evident, not immutable against a database owner or privileged file
  rewrite. Deployments must restrict database and directory access and maintain
  backups appropriate to their recovery requirements.
- Scanner adapters parse scanner output and feed the shared pipeline. The
  synthetic fixtures verify the supported formats, but scanner-version-specific
  behavior still requires validation against representative exports.
- Risk scores and decisions are contextual prioritization aids, not proof of
  exploitability or a guarantee of security.
- Completion of M0–M4 does not mean CTM is production-ready.
