def calculate_impact(finding, asset) -> float:
    value = 2.0 + max(0, min(4, asset.criticality - 1))
    if asset.data_classification in ("confidential", "restricted"):
        value += 2.0
    if finding.vulnerability.get("impact") in ("high", "critical"):
        value += 2.0
    if finding.evidence.get("secret_exposed"):
        value += 2.0
    return max(0.0, min(10.0, value))
