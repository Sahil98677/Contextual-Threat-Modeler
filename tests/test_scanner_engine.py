import json
from pathlib import Path

from ctm.scanner_engine import run_scanner, run_scanner_dicts


def test_nuclei_export_reaches_risk_engine(tmp_path: Path):
    path = tmp_path / "nuclei.jsonl"
    path.write_text(
        json.dumps({
            "host": "api.example.test",
            "path": "/api/users",
            "service": "https",
            "severity": "critical",
            "internet_facing": True,
            "authentication_required": False,
            "cve": "CVE-2026-0001",
            "impact": "critical",
            "exploit_available": True,
            "attack_complexity": "low",
        }),
        encoding="utf-8",
    )

    results = run_scanner("nuclei", path)

    assert len(results) == 1
    finding = results[0]
    assert finding.id == "NUCLEI-0001"
    assert finding.score > 0
    assert finding.confidence > 0
    assert finding.decision in {
        "TEST_IMMEDIATELY",
        "PRIORITIZE_VALIDATION",
        "INVESTIGATE",
        "MONITOR",
    }
    assert isinstance(finding.threats, list)
    assert isinstance(finding.attack_techniques, list)
    assert isinstance(finding.attack_paths, list)


def test_scanner_dict_wrapper_is_json_serializable(tmp_path: Path):
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps({
            "host": "10.0.0.10",
            "severity": "high",
            "cve": "CVE-2026-0002",
        }),
        encoding="utf-8",
    )

    results = run_scanner_dicts("generic-json", path)

    assert len(results) == 1
    assert results[0]["id"] == "GENERIC-JSON-0001"
    assert "score" in results[0]
    assert "decision" in results[0]
    assert "threats" in results[0]
    assert "attack_techniques" in results[0]
