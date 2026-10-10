
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
