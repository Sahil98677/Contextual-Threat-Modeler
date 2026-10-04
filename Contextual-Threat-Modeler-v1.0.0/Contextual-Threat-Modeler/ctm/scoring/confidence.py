STATUS_CONFIDENCE = {
    "discovered": 0.35,
    "suspected": 0.60,
    "validated": 0.80,
    "confirmed": 0.95,
}


def calculate_confidence(finding) -> float:
    return STATUS_CONFIDENCE.get(finding.vulnerability.get("status", "discovered"), 0.35)
