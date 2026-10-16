from __future__ import annotations

import json

from ctm.decision.decision_engine import risk_level
from ctm.engine import run
from ctm.reporting.html_report import render_html
from ctm.reporting.json_report import render_json
from ctm.reporting.sarif_report import render_sarif
from ctm.scanner_validation import summarize_findings
from ctm_dashboard import (
    _path_markup,
    build_dashboard_summary,
    finding_table_rows,
)


def test_dashboard_summary_uses_actual_engine_results() -> None:
    findings = run("mock_inputs")
    dashboard = build_dashboard_summary(findings)
    existing = summarize_findings(findings)

    assert dashboard["total"] == existing["total_findings"]
    assert dashboard["average_score"] == round(existing["average_score"], 1)
    assert dashboard["critical_high"] == (
        existing["risk_levels"].get("CRITICAL", 0)
        + existing["risk_levels"].get("HIGH", 0)
    )
    assert sum(dashboard["risk_levels"].values()) == len(findings)
    assert all(risk_level(item.score) in dashboard["risk_levels"] for item in findings)


def test_findings_table_contains_engine_values_and_remediation_priority() -> None:
    findings = run("mock_inputs")
    rows = finding_table_rows(findings)

    assert len(rows) == len(findings)
    if findings:
        first = rows[0]
        assert first["ID"] == findings[0].id
        assert first["Score"] == round(findings[0].score, 1)
        assert first["Decision"] == findings[0].decision
        assert first["Priority"] in {"P1", "P2", "P3", "P4"}


def test_attack_paths_are_deduplicated_by_path_id() -> None:
    findings = run("mock_inputs")
    summary = build_dashboard_summary(findings)
    path_ids = [path["path_id"] for path in summary["attack_paths"]]
    assert len(path_ids) == len(set(path_ids))


def test_attack_path_markup_escapes_untrusted_text_and_labels_candidate() -> None:
    markup = _path_markup({
        "path_id": "PATH-001",
        "path_score": 72.5,
        "classification": "inferred_candidate",
        "nodes": ["<script>alert(1)</script>", "target & asset"],
        "evidence": {"basis": "<not html>"},
        "limitations": ["candidate only"],
    })
    assert "<script>" not in markup
    assert "&lt;script&gt;" in markup
    assert "target &amp; asset" in markup
    assert "inferred candidate" in markup
    assert "Priority score 72.5 / 100" in markup
    assert "not a probability" in markup


def test_dashboard_does_not_change_existing_report_renderers() -> None:
    findings = run("mock_inputs")
    json_payload = json.loads(render_json(findings))
    html_report = render_html(findings)
    sarif_payload = json.loads(render_sarif(findings))

    assert json_payload["report"]["finding_count"] == len(findings)
    assert "Contextual Threat Modeler" in html_report
    assert sarif_payload["version"] == "2.1.0"
    assert isinstance(sarif_payload["runs"][0]["results"], list)


def test_empty_results_are_supported() -> None:
    summary = build_dashboard_summary([])
    assert summary["total"] == 0
    assert summary["critical_high"] == 0
    assert summary["average_score"] == 0.0
    assert summary["attack_paths"] == []
    assert finding_table_rows([]) == []
