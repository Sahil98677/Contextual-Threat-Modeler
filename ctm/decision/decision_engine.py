DECISIONS = (
    "TEST_IMMEDIATELY",
    "PRIORITIZE_VALIDATION",
    "INVESTIGATE",
    "MONITOR",
)


def decide(score: float, confidence: float) -> str:
    if score >= 85 and confidence >= 0.60:
        return "TEST_IMMEDIATELY"
    if score >= 70:
        return "PRIORITIZE_VALIDATION"
    if score >= 45:
        return "INVESTIGATE"
    return "MONITOR"


def risk_level(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 45:
        return "MEDIUM"
    return "LOW"
