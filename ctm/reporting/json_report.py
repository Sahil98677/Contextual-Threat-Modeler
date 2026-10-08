import json

from ..scanner_validation import summarize_findings


def render_json(results) -> str:
    results = list(results)
    payload = {
        "report": {
            "product": "Contextual Threat Modeler",
            "report_type": "security_decision",
            "finding_count": len(results),
            "summary": summarize_findings(results),
        },
        "findings": [finding.to_dict() for finding in results],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
