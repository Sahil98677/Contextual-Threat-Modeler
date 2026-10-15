from ..verification import has_controlled_verification

STATUS_CONFIDENCE = {
    "discovered": 0.35,
    "suspected": 0.60,
    "validated": 0.80,
    "confirmed": 0.95,
}

SCANNER_REPORTED_CONFIDENCE_CAP = 0.60


def calculate_confidence(finding) -> float:
    """Calculate confidence using status and controlled verification evidence."""
    status = finding.vulnerability.get("status", "discovered")
    confidence = STATUS_CONFIDENCE.get(status, 0.35)

    provenance = finding.evidence.get("validation_provenance", {})
    if not isinstance(provenance, dict) or not provenance:
        return confidence

    if not has_controlled_verification(provenance):
        return min(confidence, SCANNER_REPORTED_CONFIDENCE_CAP)

    return confidence
