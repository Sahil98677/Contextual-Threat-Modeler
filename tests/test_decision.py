from ctm.decision.decision_engine import decide, risk_level


def test_decision_thresholds():
    assert decide(90, 0.80) == "TEST_IMMEDIATELY"
    assert decide(75, 0.35) == "PRIORITIZE_VALIDATION"
    assert decide(50, 0.35) == "INVESTIGATE"
    assert decide(20, 0.95) == "MONITOR"


def test_risk_levels():
    assert risk_level(90) == "CRITICAL"
    assert risk_level(75) == "HIGH"
    assert risk_level(50) == "MEDIUM"
    assert risk_level(20) == "LOW"
