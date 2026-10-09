from ctm.context.severity import normalize_severity
from ctm.scanner import normalize_scanner_records


def test_nessus_numeric_severity_and_risk_factor_are_preserved():
    record = {
        "host": "10.0.0.1",
        "severity": 3,
        "risk_factor": "High",
        "plugin_name": "TLS finding",
    }
    finding = normalize_scanner_records([record], "nessus")["findings"][0]
    assert finding["vulnerability"]["severity"] == "high"
    assert finding["vulnerability"]["status"] == "validated"
    assert finding["vulnerability"]["risk_factor"] == "High"


def test_nessus_numeric_severity_mapping():
    assert [normalize_severity(n, "nessus") for n in range(5)] == [
        "info", "low", "medium", "high", "critical"
    ]


def test_qualys_numeric_severity_mapping():
    assert [normalize_severity(n, "qualys-xml") for n in range(1, 6)] == [
        "info", "low", "medium", "high", "critical"
    ]


def test_risk_factor_fallback_when_severity_missing():
    assert normalize_severity(None, "nessus", "High") == "high"


def test_valid_severity_is_not_overridden_by_conflicting_risk_factor():
    assert normalize_severity(2, "nessus", "High") == "medium"


def test_unknown_generic_numeric_severity_does_not_guess_scale():
    assert normalize_severity(4, "generic-json") == "info"


def test_scanner_context_fields_are_retained_when_supplied():
    data = normalize_scanner_records([{
        "host": "container-01",
        "severity": "HIGH",
        "criticality": 5,
        "internet_facing": True,
        "authentication_required": False,
        "production": True,
        "controls": {"waf": True},
    }], "trivy")
    asset = next(iter(data["assets"].values()))
    finding = data["findings"][0]
    assert asset["criticality"] == 5
    assert asset["production"] is True
    assert finding["exposure"]["internet_facing"] is True
    assert finding["exposure"]["authentication_required"] is False
    assert finding["controls"]["waf"] is True
