import json

import pytest

from ctm.engine import run
from ctm.reporting.html_report import render_html
from ctm.reporting.json_report import render_json


@pytest.fixture
def sample_results():
    return run("mock_inputs")


def test_json_report_contains_summary_and_findings(sample_results):
    payload = json.loads(render_json(sample_results))
    assert payload["report"]["product"] == "Contextual Threat Modeler"
    assert payload["report"]["finding_count"] == len(sample_results)
    assert "summary" in payload["report"]
    assert len(payload["findings"]) == len(sample_results)


def test_html_report_contains_summary_and_findings(sample_results):
    report = render_html(sample_results)
    assert "Contextual Threat Modeler" in report
    assert "Risk distribution" in report
    assert "Decisions" in report
    assert "TEST_IMMEDIATELY" in report


def test_html_report_handles_empty_results():
    report = render_html([])
    assert "No findings" in report
