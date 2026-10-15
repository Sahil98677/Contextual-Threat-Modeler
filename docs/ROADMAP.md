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
| M6 | Persistent audit storage | Planned. Store audit events durably in access-controlled, append-only storage with integrity checks and recovery behavior. |
| M7 | Unified scanner ingestion | Assessment and integration milestone. Connect supported adapters through the common schema and registry, normalize records into CTM assets and findings, and verify they reach the risk pipeline. |
| M8 | Contextual risk calibration | Planned. Strengthen and document how exposure, authentication, asset criticality, data sensitivity, exploitability, and controls affect risk; use deterministic regression tests. |
| M9 | STRIDE and MITRE ATT&CK mapping | Planned. Improve threat and technique mapping with traceable evidence and tests. |
| M10 | Attack-path analysis | Planned. Correlate assets, endpoints, trust relationships, controls, and findings into reproducible, evidence-backed candidate paths. |
| M11 | Actionable decisions and reporting | Planned. Deliver remediation priorities, concise rationales, and schema-validated JSON, SARIF, and analyst-facing reports. |
| M12 | Release hardening and adoption | Planned. Complete documentation, threat model, safe fixtures, packaging, reproducible CI, security checks, contribution guidance, and release-readiness work. |

## Recommended implementation order

The milestone numbers describe scope, not necessarily execution order. Work in
this dependency order:

1. **M5–M6 — Close verification trust and audit-storage gaps.**
2. **M7 — Verify that scanner exports reliably reach the risk engine.**
3. **M8 — Calibrate risk using reliable normalized inputs.**
4. **M9–M10 — Improve threat context and attack-chain reasoning.**
5. **M11 — Deliver actionable decisions and reporting.**
6. **M12 — Prepare for a reliable public release.**

M7 should be addressed early: adapter availability alone does not prove that
all supported exports flow consistently through normalization, enrichment,
scoring, decisions, and reporting.

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
- Hash chaining makes a verification history tamper-evident, not immutable.
  Production deployments need access-controlled, append-only durable storage.
- Scanner adapters parse scanner output; adapter availability alone does not
  mean every output is integrated into the complete risk pipeline.
- Risk scores and decisions are contextual prioritization aids, not proof of
  exploitability or a guarantee of security.
- Completion of M0–M4 does not mean CTM is production-ready.
