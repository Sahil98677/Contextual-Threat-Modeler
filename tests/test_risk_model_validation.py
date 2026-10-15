from typing import Any

from ctm.models import Asset, Finding
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
