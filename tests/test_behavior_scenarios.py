import json
from pathlib import Path
from typing import Any

import pytest

from ctm.decision.decision_engine import decide, risk_level
from ctm.engine import run
from ctm.ingestion import normalize, validate_inputs
from ctm.models import Asset, Finding
from ctm.scoring.risk import calculate_risk

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_INPUTS = REPOSITORY_ROOT / "behavior_test_inputs.json"
SCENARIO_FILES = (
    "assets.json",
    "endpoints.json",
    "header_data.json",
    "secrets.json",
    "vulnerabilities.json",
    "controls.json",
)


def _write_scenario(tmp_path: Path, name: str) -> None:
    bundle = json.loads(SCENARIO_INPUTS.read_text(encoding="utf-8"))
    scenario = bundle["scenarios"][name]
    for filename in SCENARIO_FILES:
        (tmp_path / filename).write_text(
            json.dumps(scenario[filename]),
            encoding="utf-8",
        )


@pytest.mark.parametrize(
    ("scenario_name", "expected_score", "expected_decision"),
    [
        ("internal_low_impact_discovery", 6.0, "MONITOR"),
        ("internet_facing_critical_confirmed_exploit", 100.0, "TEST_IMMEDIATELY"),
        ("critical_finding_with_controls", 49.1, "INVESTIGATE"),
        ("discovered_secret_low_criticality_asset", 85.0, "PRIORITIZE_VALIDATION"),
    ],
)
def test_behavior_scenarios_produce_expected_score_and_decision(
    tmp_path: Path,
    scenario_name: str,
    expected_score: float,
    expected_decision: str,
) -> None:
    _write_scenario(tmp_path, scenario_name)

    findings = run(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].score == expected_score
    assert findings[0].decision == expected_decision


def test_multi_finding_scenario_ranks_findings_as_expected(tmp_path: Path) -> None:
    _write_scenario(tmp_path, "multi_finding_end_to_end")

    findings = run(str(tmp_path))

    assert [(item.id, item.score, item.decision) for item in findings] == [
        ("CRIT", 100.0, "TEST_IMMEDIATELY"),
        ("SECRET", 85.0, "PRIORITIZE_VALIDATION"),
        ("LOW", 4.0, "MONITOR"),
    ]


def test_minimal_input_uses_safe_optional_field_defaults() -> None:
    raw = {
        "assets": [{"id": "A1", "name": "Minimal asset"}],
        "endpoints": [{"path": "/minimal"}],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [],
        "controls": [],
    }

    finding = normalize(raw)["findings"][0]

    assert finding["method"] == "GET"
    assert finding["endpoint_type"] == "unknown"
    assert finding["asset_id"] == "A1"
    assert finding["exposure"] == {
        "internet_facing": False,
        "authentication_required": True,
        "trust_zone": "internal",
    }
    assert finding["vulnerability"]["status"] == "discovered"
    assert finding["controls"]["security_headers"] == "unknown"


def test_multiple_vulnerabilities_on_one_endpoint_get_distinct_finding_ids() -> None:
    raw = {
        "assets": [{"id": "A1", "name": "Asset"}],
        "endpoints": [{"path": "/same"}],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [
            {"path": "/same", "name": "First"},
            {"path": "/same", "name": "Second"},
        ],
        "controls": [],
    }

    findings = normalize(raw)["findings"]

    assert [item["id"] for item in findings] == ["F-001-V01", "F-001-V02"]
    assert [item["vulnerability"]["name"] for item in findings] == ["First", "Second"]


def test_invalid_vulnerability_status_is_rejected() -> None:
    raw = {
        "assets": [{"id": "A1", "name": "Asset"}],
        "endpoints": [{"path": "/x"}],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [{"path": "/x", "status": "exploited"}],
        "controls": [],
    }

    with pytest.raises(ValueError, match="Invalid vulnerability status"):
        validate_inputs(raw)


@pytest.mark.parametrize(
    "exposure",
    [
        {"internet_facing": True},
        {"authentication_required": False},
        {"trust_zone": "DMZ"},
    ],
)
def test_each_exposure_factor_increases_likelihood(exposure: dict[str, object]) -> None:
    base = Finding(id="F", asset_id="A", method="GET", path="/x", endpoint_type="api")
    exposed = Finding(
        id="F",
        asset_id="A",
        method="GET",
        path="/x",
        endpoint_type="api",
        exposure=exposure,
    )
    asset = Asset(id="A", name="Asset")

    calculate_risk(base, asset)
    calculate_risk(exposed, asset)

    assert exposed.likelihood > base.likelihood


@pytest.mark.parametrize(
    "vulnerability",
    [
        {"exploit_available": True},
        {"attack_complexity": "low"},
        {"status": "suspected"},
        {"status": "validated"},
        {"status": "confirmed"},
    ],
)
def test_vulnerability_evidence_increases_likelihood(
    vulnerability: dict[str, object],
) -> None:
    base = Finding(id="F", asset_id="A", method="GET", path="/x", endpoint_type="api")
    supported = Finding(
        id="F",
        asset_id="A",
        method="GET",
        path="/x",
        endpoint_type="api",
        vulnerability=vulnerability,
    )
    asset = Asset(id="A", name="Asset")

    calculate_risk(base, asset)
    calculate_risk(supported, asset)

    assert supported.likelihood > base.likelihood


@pytest.mark.parametrize(
    "control",
    ["waf", "file_validation", "av_scanning", "mfa"],
)
def test_each_supported_control_reduces_a_high_risk_score(control: str) -> None:
    finding_data: dict[str, Any] = {
        "id": "F",
        "asset_id": "A",
        "method": "POST",
        "path": "/upload",
        "endpoint_type": "file_upload",
        "exposure": {"internet_facing": True, "authentication_required": False},
        "vulnerability": {
            "status": "confirmed",
            "exploit_available": True,
            "attack_complexity": "low",
            "impact": "critical",
        },
    }
    without_control = Finding(**finding_data)
    with_control = Finding(**finding_data, controls={control: True})
    asset = Asset(id="A", name="Production", criticality=5, data_classification="restricted")

    calculate_risk(without_control, asset)
    calculate_risk(with_control, asset)

    assert with_control.score < without_control.score


@pytest.mark.parametrize(
    ("score", "expected_decision", "expected_risk"),
    [
        (44.99, "MONITOR", "LOW"),
        (45.0, "INVESTIGATE", "MEDIUM"),
        (69.99, "INVESTIGATE", "MEDIUM"),
        (70.0, "PRIORITIZE_VALIDATION", "HIGH"),
        (84.99, "PRIORITIZE_VALIDATION", "HIGH"),
        (85.0, "TEST_IMMEDIATELY", "CRITICAL"),
    ],
)
def test_decision_and_risk_threshold_boundaries(
    score: float,
    expected_decision: str,
    expected_risk: str,
) -> None:
    assert decide(score, 0.95) == expected_decision
    assert risk_level(score) == expected_risk


def test_immediate_test_decision_requires_minimum_confidence() -> None:
    assert decide(85.0, 0.59) == "PRIORITIZE_VALIDATION"
    assert decide(85.0, 0.60) == "TEST_IMMEDIATELY"
