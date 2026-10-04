import json


def render_json(results) -> str:
    return json.dumps([finding.to_dict() for finding in results], indent=2)
