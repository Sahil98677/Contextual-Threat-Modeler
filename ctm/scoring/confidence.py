STATUS_CONFIDENCE = {
    "discovered": 0.35,
    "suspected": 0.60,
    "validated": 0.80,
    "confirmed": 0.95,
}

SCANNER_REPORTED_CONFIDENCE_CAP = 0.60


def calculate_confidence(finding) -> float:
    """Calculate confidence while accounting for validation provenance."""
    status = finding.vulnerability.get("status", "discovered")
    confidence = STATUS_CONFIDENCE.get(status, 0.35)

    provenance = finding.evidence.get("validation_provenance", {})
    if not isinstance(provenance, dict):
        return confidence

    if (
        provenance.get("status_origin") == "scanner_reported"
        and provenance.get("independently_verified") is not True
    ):
        return min(confidence, SCANNER_REPORTED_CONFIDENCE_CAP)

    if (
        provenance.get("independently_verified") is True
        and provenance.get("status_origin") != "ctm_verified"
    ):
        return min(confidence, SCANNER_REPORTED_CONFIDENCE_CAP)

    return confidence
