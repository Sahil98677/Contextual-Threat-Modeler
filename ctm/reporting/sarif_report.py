"""SARIF 2.1.0 output for security findings."""
from __future__ import annotations

import json
import re
from typing import Any

from jsonschema import validate

from ..decision.decision_engine import risk_level
from .remediation import build_remediation_plan
from .schemas import SARIF_REPORT_SCHEMA

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

LEVEL_BY_RISK = {
    "CRITICAL": "error",
    "HIGH": "warning",
    "MEDIUM": "note",
    "LOW": "note",
}


def _rule_id(finding: Any) -> str:
    cwe = finding.vulnerability.get("cwe")
    if isinstance(cwe, str) and re.fullmatch(r"CWE-\d+", cwe.strip(), re.IGNORECASE):
        return cwe.strip().upper()
    endpoint_type = re.sub(r"[^A-Za-z0-9_.-]+", "-", finding.endpoint_type).strip("-")
    return f"CTM/{endpoint_type or 'finding'}"


def render_sarif(results) -> str:
    findings = sorted(results, key=lambda item: item.id)
    remediation_by_id = {
        item["finding_id"]: item for item in build_remediation_plan(findings)
    }
    rules: dict[str, dict[str, Any]] = {}
    sarif_results = []

    for finding in findings:
        rule_id = _rule_id(finding)
        name = (
            finding.vulnerability.get("name")
            or finding.vulnerability.get("title")
            or finding.endpoint_type
            or "Security finding"
        )
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": str(name),
                "shortDescription": {"text": str(name)},
                "defaultConfiguration": {"level": LEVEL_BY_RISK[risk_level(finding.score)]},
            },
        )
        remediation = remediation_by_id[finding.id]
        rationale = remediation["rationale"]
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": LEVEL_BY_RISK[risk_level(finding.score)],
                "message": {
                    "text": (
                        f"{remediation['priority']} remediation priority: "
                        f"{remediation['action']} Context: {rationale}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.path or ".",
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": f"{finding.method} {finding.path}",
                                "kind": "url",
                            }
                        ],
                    }
                ],
                "properties": {
                    "findingId": finding.id,
                    "assetId": finding.asset_id,
                    "riskScore": finding.score,
                    "confidence": finding.confidence,
                    "decision": finding.decision,
                    "priority": remediation["priority"],
                    "remediation": remediation["action"],
                    "rationale": finding.rationale,
                    "threats": finding.threats,
                    "attackTechniques": finding.attack_techniques,
                },
            }
        )

    payload = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Contextual Threat Modeler",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    validate(instance=payload, schema=SARIF_REPORT_SCHEMA)
    return json.dumps(payload, indent=2, sort_keys=True)
