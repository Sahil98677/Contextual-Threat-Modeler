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
