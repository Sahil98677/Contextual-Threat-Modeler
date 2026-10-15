def calculate_impact(finding, asset) -> float:
    value = 2.0 + max(0, min(4, asset.criticality - 1))
    classification = str(asset.data_classification).strip().lower()
    if classification in {"confidential", "restricted", "unknown"}:
        value += 2.0
    if finding.vulnerability.get("impact") in ("high", "critical"):
        value += 2.0
    if finding.evidence.get("secret_exposed"):
        value += 2.0
    return max(0.0, min(10.0, value))
