# Phase 6.4 — Scanner Reliability and Input Hardening

## Changes in this patch

- Normalize Nessus numeric severity using the Nessus 0–4 scale.
- Normalize Qualys numeric severity using the Qualys 1–5 scale.
- Use `risk_factor` only as a fallback when severity is missing or unknown.
- Preserve scanner context fields when the input record supplies them.
- Replace duplicated boolean parsers with `ctm.context.values.as_bool`.
- Harden Nessus and Qualys XML parsing with `defusedxml`.
- Centralize risk thresholds used by decisions, trends, and scanner summaries.
- Add regression tests for severity mapping and hostile XML.
- Add Ruff, Bandit, and a scoped mypy check to CI.

## Context limitation

Scanner exports do not reliably establish whether an asset is production, internet-facing,
authenticated, or business-critical. This patch preserves these fields when supplied by an
adapter record, but does not guess missing environmental context. Supply authoritative context
through a trusted inventory/CMDB enrichment step before using CTM scores for prioritization.

## Secret exposure policy

The existing minimum score of 85 for `secret_exposed` is retained intentionally in this patch
because changing it is a policy decision. A follow-up should distinguish confirmed active
credentials from suspected, revoked, or non-sensitive tokens and define how control modifiers
interact with those cases.

## Validation

Run `pytest -q`, `ruff check adapters ctm tests`, `bandit -q -r adapters ctm`, and
`mypy --ignore-missing-imports --follow-imports=silent ctm/context/severity.py ctm/scanner.py`.
Review all CI results before merging.
