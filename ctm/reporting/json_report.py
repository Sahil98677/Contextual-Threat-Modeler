import json

from jsonschema import validate

from ..scanner_validation import summarize_findings
from .remediation import build_remediation_plan
from .schemas import CTM_REPORT_SCHEMA


def render_json(results, trend=None) -> str:
    results = list(results)
    payload = {
        "report": {
            "product": "Contextual Threat Modeler",
            "report_type": "security_decision",
            "finding_count": len(results),
            "summary": summarize_findings(results),
        },
        "findings": [finding.to_dict() for finding in results],
        "remediation_plan": build_remediation_plan(results),
    }
    if trend is not None:
        payload["trend"] = trend
    validate(instance=payload, schema=CTM_REPORT_SCHEMA)
    return json.dumps(payload, indent=2, sort_keys=True)
