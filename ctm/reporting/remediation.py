"""Deterministic remediation priorities and guidance for analyst reports."""
from __future__ import annotations

from typing import Any

PRIORITY_BY_DECISION = {
    "TEST_IMMEDIATELY": "P1",
    "PRIORITIZE_VALIDATION": "P2",
    "INVESTIGATE": "P3",
    "MONITOR": "P4",
}

ACTION_BY_CWE = {
    "CWE-89": (
        "Use parameterized queries for database access, then regression-test the "
        "affected operation."
    ),
    "CWE-434": (
        "Restrict uploads by type and content, store uploaded files outside executable "
        "web paths, and verify the controls."
    ),
    "CWE-639": (
        "Authorize every object access against the authenticated principal and test "
        "cross-user access denial."
    ),
}

ACTION_BY_DECISION = {
    "TEST_IMMEDIATELY": (
        "Validate safely in an authorized test environment; if confirmed, remediate "
        "and retest."
    ),
    "PRIORITIZE_VALIDATION": (
        "Prioritize validation of the affected version, configuration, and reachable "
        "attack surface; remediate if confirmed."
    ),
    "INVESTIGATE": (
        "Review the available evidence and determine affected scope and reachability "
        "before selecting a fix."
    ),
    "MONITOR": (
        "Track and reassess if exposure, asset criticality, or validation evidence changes."
    ),
}


def remediation_for(finding: Any) -> dict[str, Any]:
    """Return report guidance without asserting a finding is exploitable."""
    decision = finding.decision
    vulnerability = finding.vulnerability
    cwe = vulnerability.get("cwe")
    cwe_key = cwe.strip().upper() if isinstance(cwe, str) else ""
    cwe_action = ACTION_BY_CWE.get(cwe_key)
    action = (
        f"If confirmed, {cwe_action}"
        if cwe_action
        else ACTION_BY_DECISION[decision]
    )
    rationale = " ".join(finding.rationale[:2]).strip()

    return {
        "finding_id": finding.id,
        "priority": PRIORITY_BY_DECISION[decision],
        "score": finding.score,
        "decision": decision,
        "action": action,
        "rationale": rationale or "No additional contextual rationale was recorded.",
    }


def build_remediation_plan(findings: list[Any]) -> list[dict[str, Any]]:
    """Prioritize recommendations by decision priority, score, then stable ID."""
    plans = [remediation_for(finding) for finding in findings]
    priority_order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
    return sorted(
        plans,
        key=lambda plan: (
            priority_order[plan["priority"]],
            -plan["score"],
            plan["finding_id"],
        ),
    )
