from ctm.context.asset import build_asset
from ctm.context.controls import control_modifier
from ctm.context.exposure import exposure_factors


def test_asset_criticality_is_bounded():
    asset = build_asset({"id": "A", "name": "x", "criticality": 99})
    assert asset.criticality == 5


def test_asset_string_false_production_is_false():
    asset = build_asset({"id": "A", "name": "x", "production": "false"})
    assert asset.production is False


def test_asset_string_true_production_is_true():
    asset = build_asset({"id": "A", "name": "x", "production": "true"})
    assert asset.production is True


def test_exposure_factors():
    factors = exposure_factors(
        {"internet_facing": True, "authentication_required": False, "trust_zone": "DMZ"}
    )
    assert factors["total"] == 6.0


def test_exposure_factors_parse_string_booleans():
    factors = exposure_factors({
        "internet_facing": "false",
        "authentication_required": "false",
        "trust_zone": "DMZ",
    })
    assert factors["internet_facing"] == 0.0
    assert factors["unauthenticated"] == 2.0
    assert factors["total"] == 3.0


def test_waf_string_false_does_not_reduce_modifier():
    assert control_modifier({"waf": "false"}) == 1.0


def test_waf_string_true_reduces_modifier():
    assert control_modifier({"waf": "true"}) == 0.90


def test_control_string_false_values_do_not_reduce_modifier():
    controls = {
        "waf": "false",
        "file_validation": "false",
        "av_scanning": "false",
        "mfa": "false",
    }
    assert control_modifier(controls) == 1.0


def test_control_string_true_values_apply_modifiers():
    controls = {
        "waf": "true",
        "file_validation": "true",
        "av_scanning": "true",
        "mfa": "true",
    }
    assert control_modifier(controls) == 0.90 * 0.75 * 0.85 * 0.95
