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


def test_unknown_exposure_is_scored_as_risk_positive():
    assert exposure_factors({})["total"] == 6.0


def test_explicit_low_exposure_is_distinct_from_unknown():
    unknown = exposure_factors({})
    assessed_low = exposure_factors(
        {
            "internet_facing": False,
            "authentication_required": True,
            "trust_zone": "internal",
        }
    )

    assert unknown["total"] > assessed_low["total"]


def test_waf_string_false_does_not_reduce_modifier():
    assert control_modifier({"waf": "false"}, "api", {"cwe": "CWE-89"}) == 1.0


def test_waf_string_true_reduces_modifier():
    assert control_modifier({"waf": "true"}, "api", {"cwe": "CWE-89"}) == 0.90


def test_waf_does_not_reduce_findings_without_mapped_vulnerability_evidence():
    assert control_modifier({"waf": True}, "api", {}) == 1.0


def test_control_string_false_values_do_not_reduce_modifier():
    controls = {
        "waf": "false",
        "file_validation": "false",
        "av_scanning": "false",
        "mfa": "false",
    }
    assert control_modifier(controls, "file_upload", {"cwe": "CWE-434"}) == 1.0


def test_file_controls_do_not_reduce_unrelated_findings():
    controls = {"file_validation": True, "av_scanning": True}

    assert control_modifier(controls, "api", {"cwe": "CWE-89"}) == 1.0


def test_file_controls_do_not_reduce_remote_code_execution_findings():
    controls = {"file_validation": True, "av_scanning": True}

    assert control_modifier(controls, "file_upload", {"cwe": "CWE-94"}) == 1.0


def test_mfa_does_not_reduce_non_authentication_findings():
    assert control_modifier({"mfa": True}, "admin", {"cwe": "CWE-89"}) == 1.0


def test_mfa_reduces_credential_findings_on_authentication_endpoints():
    assert control_modifier(
        {"mfa": True}, "admin", {"cwe": "CWE-522"}
    ) == 0.95


def test_security_headers_only_reduce_relevant_admin_findings():
    assert control_modifier(
        {"security_headers": "strong"}, "admin", {"cwe": "CWE-79"}
    ) == 0.90
    assert control_modifier(
        {"security_headers": "strong"}, "api", {"cwe": "CWE-89"}
    ) == 1.0


def test_relevant_file_controls_apply_together():
    controls = {"file_validation": True, "av_scanning": True}

    assert control_modifier(
        controls, "file_upload", {"cwe": "CWE-434"}
    ) == 0.75 * 0.85
