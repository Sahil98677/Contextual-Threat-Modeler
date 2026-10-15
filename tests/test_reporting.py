import json

import pytest
from jsonschema import ValidationError, validate

from ctm.engine import run
from ctm.reporting.console import render_console
from ctm.reporting.html_report import render_html
from ctm.reporting.json_report import render_json
from ctm.reporting.remediation import build_remediation_plan
from ctm.reporting.sarif_report import render_sarif
from ctm.reporting.schemas import CTM_REPORT_SCHEMA


@pytest.fixture
def sample_results():
    return run("mock_inputs")


def test_json_report_contains_summary_and_findings(sample_results):
    payload = json.loads(render_json(sample_results))
    assert payload["report"]["product"] == "Contextual Threat Modeler"
    assert payload["report"]["finding_count"] == len(sample_results)
    assert "summary" in payload["report"]
    assert len(payload["findings"]) == len(sample_results)
    assert len(payload["remediation_plan"]) == len(sample_results)
    validate(instance=payload, schema=CTM_REPORT_SCHEMA)
    assert payload["remediation_plan"] == build_remediation_plan(sample_results)


def test_json_report_schema_rejects_missing_remediation_plan(sample_results):
    payload = json.loads(render_json(sample_results))
    del payload["remediation_plan"]

    with pytest.raises(ValidationError):
        validate(instance=payload, schema=CTM_REPORT_SCHEMA)


def test_sarif_report_contains_prioritized_findings(sample_results):
    payload = json.loads(render_sarif(sample_results))

    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "Contextual Threat Modeler"
    assert len(payload["runs"][0]["results"]) == len(sample_results)
    for result in payload["runs"][0]["results"]:
        assert result["level"] in {"error", "warning", "note"}
        assert result["properties"]["priority"] in {"P1", "P2", "P3", "P4"}
        assert result["message"]["text"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_report_is_deterministic_and_sorted_by_finding_id(sample_results):
    first = json.loads(render_sarif(sample_results))
    second = json.loads(render_sarif(list(reversed(sample_results))))

    assert first == second
    finding_ids = [
        result["properties"]["findingId"]
        for result in first["runs"][0]["results"]
    ]
    assert finding_ids == sorted(finding_ids)


def test_sarif_report_handles_empty_results():
    payload = json.loads(render_sarif([]))

    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"] == []
    assert payload["runs"][0]["tool"]["driver"]["rules"] == []


def test_remediation_plan_uses_decision_order_and_cwe_guidance(sample_results):
    plan = build_remediation_plan(sample_results)
    priorities = [item["priority"] for item in plan]

    assert priorities == sorted(priorities, key=lambda value: int(value[1:]))
    for item in plan:
        if item["finding_id"] == "F-001":
            assert "If confirmed" in item["action"]
            assert "uploads" in item["action"]
            break
    else:
        pytest.fail("Expected the mock upload finding F-001 to appear in the plan")


def test_html_report_contains_summary_and_findings(sample_results):
    report = render_html(sample_results)
    assert "Contextual Threat Modeler" in report
    assert "Risk distribution" in report
    assert "Decisions" in report
    assert "Attack paths" in report
    assert "PATH-" in report
    assert "inferred_candidate" in report
    assert "confirmed: false" in report
    assert "not ordered as an attack chain" in report
    assert "path-summary" in report
    assert "→" not in report
    assert "Remediation priority" in report
    assert "Recommended action" in report


def test_html_report_handles_empty_results():
    report = render_html([])
    assert "No findings" in report


def test_console_report_marks_attack_paths_as_unconfirmed_candidates(sample_results):
    report = render_console(sample_results)

    assert "Classification: inferred_candidate (confirmed: False)" in report
    assert "Candidate correlation only" in report
    assert " -> " not in report
    assert "Remediation: P" in report


def test_html_report_includes_risk_trend():
    report = render_html(
        [],
        trend={
            "available": True,
            "status": "IMPROVING",
            "average_score_delta": -12.5,
            "previous_timestamp": "2026-10-08T10:00:00Z",
            "current_timestamp": "2026-10-09T10:00:00Z",
            "assets": [{"asset_id": "A-1", "status": "IMPROVING", "delta": -10.0}],
        },
    )

    assert "Risk trend: IMPROVING" in report
    assert "-12.5" in report
    assert "A-1" in report
