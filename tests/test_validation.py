import pytest

from ctm.ingestion import normalize, validate_inputs


def test_duplicate_asset_id_is_rejected():
    raw = {
        "assets": [
            {"id": "A-1", "name": "One"},
            {"id": "A-1", "name": "Duplicate"},
        ],
        "endpoints": [],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [],
        "controls": [],
    }
    with pytest.raises(ValueError, match="Duplicate asset id"):
        validate_inputs(raw)


def test_invalid_criticality_is_rejected():
    raw = {
        "assets": [{"id": "A-1", "name": "One", "criticality": 9}],
        "endpoints": [],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [],
        "controls": [],
    }
    with pytest.raises(ValueError, match="criticality"):
        validate_inputs(raw)


def test_invalid_status_is_rejected():
    raw = {
        "assets": [{"id": "A-1", "name": "One"}],
        "endpoints": [],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [{"path": "/x", "status": "exploited"}],
        "controls": [],
    }
    with pytest.raises(ValueError, match="Invalid vulnerability status"):
        validate_inputs(raw)


def test_non_array_input_section_is_rejected():
    raw = {
        "assets": [{"id": "A-1", "name": "One"}],
        "endpoints": [],
        "headers": {},
        "secrets": [],
        "vulnerabilities": [],
        "controls": [],
    }

    with pytest.raises(ValueError, match="headers must be a JSON array"):
        validate_inputs(raw)


def test_endpoint_cannot_reference_unknown_asset():
    raw = {
        "assets": [{"id": "A-1", "name": "One"}],
        "endpoints": [{"path": "/x", "asset_id": "missing"}],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [],
        "controls": [],
    }

    with pytest.raises(ValueError, match="references an unknown asset"):
        validate_inputs(raw)


def test_normalize_parses_string_boolean_exposure_values():
    raw = {
        "assets": [{"id": "A-1", "name": "One"}],
        "endpoints": [{
            "path": "/x",
            "internet_facing": "false",
            "authentication_required": "false",
        }],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [],
        "controls": [],
    }

    finding = normalize(raw)["findings"][0]

    assert finding["exposure"]["internet_facing"] is False
    assert finding["exposure"]["authentication_required"] is False


def test_normalize_parses_string_true_exposure_values():
    raw = {
        "assets": [{"id": "A-1", "name": "One"}],
        "endpoints": [{
            "path": "/x",
            "internet_facing": "true",
            "authentication_required": "true",
        }],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [],
        "controls": [],
    }

    finding = normalize(raw)["findings"][0]

    assert finding["exposure"]["internet_facing"] is True
    assert finding["exposure"]["authentication_required"] is True


def test_normalize_does_not_treat_string_false_exploit_as_available():
    raw = {
        "assets": [{"id": "A-1", "name": "One"}],
        "endpoints": [{"path": "/x", "asset_id": "A-1"}],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [{"path": "/x", "exploit_available": "false"}],
        "controls": [],
    }

    finding = normalize(raw)["findings"][0]

    assert finding["vulnerability"]["exploit_available"] is False


def test_normalize_preserves_multiple_vulnerabilities_per_endpoint():
    raw = {
        "assets": [{"id": "CUSTOM", "name": "One"}],
        "endpoints": [{"path": "/x"}],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [
            {"path": "/x", "name": "First"},
            {"path": "/x", "name": "Second"},
        ],
        "controls": [],
    }

    findings = normalize(raw)["findings"]

    assert [item["vulnerability"]["name"] for item in findings] == ["First", "Second"]
    assert [item["id"] for item in findings] == ["F-001-V01", "F-001-V02"]
    assert all(item["asset_id"] == "CUSTOM" for item in findings)
