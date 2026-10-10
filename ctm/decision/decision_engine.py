from .thresholds import (
    CRITICAL_THRESHOLD,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    MIN_CONFIDENCE_FOR_IMMEDIATE_TEST,
)

DECISIONS = (
    "TEST_IMMEDIATELY",
    "PRIORITIZE_VALIDATION",
    "INVESTIGATE",
    "MONITOR",
)


def decide(score: float, confidence: float) -> str:
    if score >= CRITICAL_THRESHOLD and confidence >= MIN_CONFIDENCE_FOR_IMMEDIATE_TEST:
        return "TEST_IMMEDIATELY"
    if score >= HIGH_THRESHOLD:
        return "PRIORITIZE_VALIDATION"
    if score >= MEDIUM_THRESHOLD:
        return "INVESTIGATE"
    return "MONITOR"


def risk_level(score: float) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"
