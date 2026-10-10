from ctm.models import Asset, Finding
from ctm.scoring.risk import calculate_risk


def test_secret_exposure_forces_high_priority():
    finding = Finding(
        id="F",
        asset_id="A",
        method="GET",
        path="/x",
        endpoint_type="api",
        evidence={"secret_exposed": True},
    )
    calculate_risk(
        finding,
        Asset(
            id="A",
            name="prod",
            criticality=5,
            data_classification="restricted",
        ),
    )
    assert finding.score >= 85


def test_controls_reduce_risk():
    base = Finding(
        id="F",
        asset_id="A",
        method="GET",
        path="/x",
        endpoint_type="api",
        exposure={"internet_facing": True, "authentication_required": False},
        vulnerability={"status": "confirmed", "impact": "high", "exploit_available": True},
    )
    controlled = Finding(**base.to_dict())
    controlled.controls = {
        "waf": True,
        "file_validation": True,
        "av_scanning": True,
        "mfa": True,
        "security_headers": "strong",
    }

    asset = Asset(id="A", name="prod", criticality=4, data_classification="confidential")
    calculate_risk(base, asset)
    calculate_risk(controlled, asset)

    assert controlled.score < base.score
