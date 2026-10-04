import json
import pytest

from ctm.ingestion import load_inputs, normalize, validate_inputs


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
