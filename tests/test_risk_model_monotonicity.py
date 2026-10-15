"""Controlled, one-factor-at-a-time checks for CTM's risk model.

These tests validate ordering properties, not calibration against real incidents.
Each pair changes one input while holding the remaining context constant.
"""

import pytest

from ctm.models import Asset, Finding
from ctm.scoring.risk import calculate_risk


def _finding(**vulnerability: object) -> Finding:
    return Finding(
        id="F-VALIDATION",
        asset_id="A-VALIDATION",
        method="GET",
        path="/validation",
        endpoint_type="api",
        vulnerability=dict(vulnerability),
    )


def _score(finding: Finding, asset: Asset) -> float:
    calculate_risk(finding, asset)
    assert 0.0 <= finding.score <= 100.0
    return finding.score


@pytest.mark.parametrize(
    ("field", "lower", "higher"),
    [
        ("internet_facing", False, True),
        ("authentication_required", True, False),
        ("trust_zone", "internal", "DMZ"),
    ],
)
def test_increased_exposure_does_not_reduce_score(
    field: str, lower: object, higher: object
) -> None:
    baseline = _finding()
    increased = _finding()
    baseline.exposure = {field: lower}
    increased.exposure = {field: higher}
    asset = Asset(id="A-VALIDATION", name="Validation asset")

    assert _score(increased, asset) > _score(baseline, asset)


@pytest.mark.parametrize(
    ("field", "lower", "higher"),
    [
        ("exploit_available", False, True),
        ("attack_complexity", "high", "low"),
        ("status", "discovered", "suspected"),
        ("status", "suspected", "validated"),
        ("status", "validated", "confirmed"),
    ],
)
def test_stronger_vulnerability_evidence_does_not_reduce_score(
    field: str, lower: object, higher: object
) -> None:
    baseline = _finding(**{field: lower})
    stronger = _finding(**{field: higher})
    asset = Asset(id="A-VALIDATION", name="Validation asset")

    assert _score(stronger, asset) > _score(baseline, asset)


def test_higher_asset_criticality_does_not_reduce_score() -> None:
    finding = _finding(impact="high")
    low = Asset(id="A-VALIDATION", name="Validation asset", criticality=1)
    high = Asset(id="A-VALIDATION", name="Validation asset", criticality=5)

    assert _score(finding, high) > _score(finding, low)


def test_sensitive_data_classification_does_not_reduce_score() -> None:
    finding = _finding(impact="high")
    internal = Asset(
        id="A-VALIDATION", name="Validation asset", data_classification="internal"
    )
    restricted = Asset(
        id="A-VALIDATION", name="Validation asset", data_classification="restricted"
    )

    assert _score(finding, restricted) > _score(finding, internal)


def test_controls_never_increase_score_for_the_same_finding() -> None:
    asset = Asset(
        id="A-VALIDATION", name="Validation asset", criticality=5,
        data_classification="restricted",
    )
    unmitigated = _finding(
        status="confirmed", exploit_available=True, attack_complexity="low", impact="critical"
    )
    mitigated = _finding(
        status="confirmed", exploit_available=True, attack_complexity="low", impact="critical"
    )
    mitigated.controls = {
        "waf": True,
        "file_validation": True,
        "av_scanning": True,
        "mfa": True,
        "security_headers": "strong",
    }

    assert _score(mitigated, asset) < _score(unmitigated, asset)


def test_score_is_capped_even_when_multiple_high_risk_factors_combine() -> None:
    finding = _finding(
        status="confirmed", exploit_available=True, attack_complexity="low", impact="critical"
    )
    finding.exposure = {
        "internet_facing": True,
        "authentication_required": False,
        "trust_zone": "DMZ",
    }
    finding.evidence = {"secret_exposed": True}
    asset = Asset(
        id="A-VALIDATION", name="Validation asset", criticality=5,
        data_classification="restricted",
    )

    assert _score(finding, asset) == 100.0
