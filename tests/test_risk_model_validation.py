from typing import Any

import pytest

from ctm.decision.decision_engine import decide, risk_level
from ctm.models import Asset, Finding
from ctm.scoring.confidence import calculate_confidence
from ctm.scoring.risk import calculate_risk


def _finding(**vulnerability: Any) -> Finding:
    return Finding(
        id="F-001",
        asset_id="A-001",
        method="POST",
        path="/upload",
        endpoint_type="file_upload",
        vulnerability=vulnerability,
    )


def _validation_finding(exposure: dict[str, Any] | None = None) -> Finding:
    return Finding(
        id="F-VALIDATION",
        asset_id="A-VALIDATION",
        method="GET",
        path="/validation",
        endpoint_type="api",
        exposure=exposure or {},
        vulnerability={
            "status": "suspected",
            "impact": "medium",
            "cwe": "CWE-522",
        },
    )


def _score(finding: Finding) -> float:
    asset = Asset(
        id="A-VALIDATION",
        name="Synthetic production asset",
        criticality=3,
        data_classification="internal",
    )
    calculate_risk(finding, asset)
    return finding.score


def test_exploit_evidence_is_explained_in_rationale() -> None:
    finding = _finding(exploit_available=True)

    calculate_risk(finding, Asset(id="A-001", name="Upload service"))

    assert any("exploit is reported as available" in item for item in finding.rationale)


def test_low_attack_complexity_is_explained_in_rationale() -> None:
    finding = _finding(attack_complexity="low")

    calculate_risk(finding, Asset(id="A-001", name="Upload service"))

    assert any("attack complexity is low" in item for item in finding.rationale)


def test_suspected_status_is_not_described_as_validated() -> None:
    finding = _finding(status="suspected")

    calculate_risk(finding, Asset(id="A-001", name="Upload service"))

    assert any("suspected but has not been validated" in item for item in finding.rationale)
    assert not any("has validation evidence" in item for item in finding.rationale)


def test_rationale_only_mentions_exploit_when_evidence_is_present() -> None:
    finding = _finding()

    calculate_risk(finding, Asset(id="A-001", name="Upload service"))

    assert not any("exploit is reported as available" in item for item in finding.rationale)


def test_unknown_exposure_is_reported_in_rationale() -> None:
    finding = _finding()

    calculate_risk(finding, Asset(id="A-001", name="Upload service"))

    assert any("Internet-facing exposure is unknown" in item for item in finding.rationale)
    assert any("Authentication requirements are unknown" in item for item in finding.rationale)
    assert any("Trust zone is unknown" in item for item in finding.rationale)


def test_unknown_exposure_is_not_scored_below_known_low_exposure() -> None:
    known_low = _validation_finding(
        {
            "internet_facing": False,
            "authentication_required": True,
            "trust_zone": "internal",
        }
    )
    unknown = _validation_finding(
        {
            "internet_facing": None,
            "authentication_required": None,
            "trust_zone": None,
        }
    )

    known_low_score = _score(known_low)
    unknown_score = _score(unknown)

    assert unknown_score > known_low_score
    assert any("unknown" in item.lower() for item in unknown.rationale)


def test_irrelevant_mfa_does_not_reduce_api_finding_score() -> None:
    exposure = {
        "internet_facing": True,
        "authentication_required": False,
        "trust_zone": "DMZ",
    }
    without_control = _validation_finding(exposure)
    with_irrelevant_control = _validation_finding(exposure)
    with_irrelevant_control.controls = {"mfa": True}

    assert _score(with_irrelevant_control) == _score(without_control)


def test_waf_does_not_reduce_unmapped_cwe_score() -> None:
    exposure = {
        "internet_facing": True,
        "authentication_required": False,
        "trust_zone": "DMZ",
    }
    without_control = _validation_finding(exposure)
    with_irrelevant_control = _validation_finding(exposure)
    without_control.vulnerability["cwe"] = "CWE-522"
    with_irrelevant_control.vulnerability["cwe"] = "CWE-522"
    with_irrelevant_control.controls = {"waf": True}

    assert _score(with_irrelevant_control) == _score(without_control)


@pytest.mark.parametrize(
    "exposure_change",
    [
        {"internet_facing": True},
        {"authentication_required": False},
        {"trust_zone": "DMZ"},
    ],
)
def test_higher_exposure_context_does_not_lower_risk_score(
    exposure_change: dict[str, Any],
) -> None:
    baseline_exposure = {
        "internet_facing": False,
        "authentication_required": True,
        "trust_zone": "internal",
    }
    baseline = _validation_finding(baseline_exposure)
    changed = _validation_finding({**baseline_exposure, **exposure_change})

    baseline_score = _score(baseline)
    changed_score = _score(changed)

    assert changed_score > baseline_score


def test_synthetic_risk_ranking_matrix() -> None:
    low = Finding(
        id="LOW",
        asset_id="A-LOW",
        method="GET",
        path="/health",
        endpoint_type="api",
        exposure={
            "internet_facing": False,
            "authentication_required": True,
            "trust_zone": "internal",
        },
        vulnerability={
            "status": "discovered",
            "impact": "low",
            "exploit_available": False,
            "attack_complexity": "high",
        },
    )
    uncertain = _validation_finding()
    critical = Finding(
        id="CRITICAL",
        asset_id="A-CRITICAL",
        method="POST",
        path="/api/upload",
        endpoint_type="api",
        exposure={
            "internet_facing": True,
            "authentication_required": False,
            "trust_zone": "DMZ",
        },
        vulnerability={
            "status": "confirmed",
            "impact": "critical",
            "exploit_available": True,
            "attack_complexity": "low",
            "cwe": "CWE-89",
        },
    )

    low_asset = Asset(
        id="A-LOW",
        name="Internal health service",
        criticality=1,
        data_classification="internal",
    )
    uncertain_asset = Asset(
        id="A-VALIDATION",
        name="Context not fully assessed",
        criticality=3,
        data_classification="internal",
    )
    critical_asset = Asset(
        id="A-CRITICAL",
        name="Critical production service",
        criticality=5,
        data_classification="restricted",
    )

    calculate_risk(low, low_asset)
    calculate_risk(uncertain, uncertain_asset)
    calculate_risk(critical, critical_asset)

    assert low.score < uncertain.score < critical.score
    assert risk_level(low.score) == "LOW"
    assert risk_level(critical.score) == "CRITICAL"
    assert any("unknown" in reason.lower() for reason in uncertain.rationale)
    assert any(
        "exploit is reported as available" in reason
        for reason in critical.rationale
    )


def test_unknown_asset_classification_increases_impact_and_is_explained() -> None:
    finding = _validation_finding()
    known_internal = Asset(
        id="A-VALIDATION",
        name="Synthetic production asset",
        criticality=3,
        data_classification="internal",
    )
    unknown_classification = Asset(
        id="A-VALIDATION",
        name="Synthetic production asset",
        criticality=3,
        data_classification="unknown",
    )

    calculate_risk(finding, known_internal)
    internal_score = finding.score
    calculate_risk(finding, unknown_classification)

    assert finding.score > internal_score
    assert any(
        "Data classification is unknown and scored conservatively." in reason
        for reason in finding.rationale
    )


@pytest.mark.parametrize(
    ("status", "expected_confidence"),
    [
        ("discovered", 0.35),
        ("suspected", 0.60),
        ("validated", 0.80),
        ("confirmed", 0.95),
    ],
)
def test_confidence_matches_vulnerability_status(
    status: str,
    expected_confidence: float,
) -> None:
    finding = _finding(status=status)

    assert calculate_confidence(finding) == expected_confidence


@pytest.mark.parametrize(
    ("status", "expected_decision"),
    [
        ("discovered", "PRIORITIZE_VALIDATION"),
        ("suspected", "TEST_IMMEDIATELY"),
        ("validated", "TEST_IMMEDIATELY"),
        ("confirmed", "TEST_IMMEDIATELY"),
    ],
)
def test_high_risk_decision_respects_status_confidence(
    status: str,
    expected_decision: str,
) -> None:
    finding = _finding(status=status)
    confidence = calculate_confidence(finding)

    assert decide(85.0, confidence) == expected_decision
