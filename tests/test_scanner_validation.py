from types import SimpleNamespace

from ctm.scanner_validation import summarize_findings


def test_summary_contains_risk_and_threat_metadata():
    findings = [
        SimpleNamespace(
            score=92,
            decision="TEST_IMMEDIATELY",
            attack_techniques=["T1190"],
            threats=["Information Disclosure"],
        ),
        SimpleNamespace(
            score=50,
            decision="INVESTIGATE",
            attack_techniques=["T1078"],
            threats=["Spoofing"],
        ),
    ]

    summary = summarize_findings(findings)

    assert summary["total_findings"] == 2
    assert summary["risk_levels"]["CRITICAL"] == 1
    assert summary["risk_levels"]["MEDIUM"] == 1
    assert summary["highest_score"] == 92
    assert "T1190" in summary["mitre_techniques"]
    assert "Information Disclosure" in summary["stride_threats"]
