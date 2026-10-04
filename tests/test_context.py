from ctm.context.asset import build_asset
from ctm.context.exposure import exposure_factors


def test_asset_criticality_is_bounded():
    asset = build_asset({"id": "A", "name": "x", "criticality": 99})
    assert asset.criticality == 5


def test_exposure_factors():
    factors = exposure_factors(
        {"internet_facing": True, "authentication_required": False, "trust_zone": "DMZ"}
    )
    assert factors["total"] == 6.0
