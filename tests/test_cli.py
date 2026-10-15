import json

from ctm_cli import main


def test_history_dir_creates_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["ctm", "--history-dir", str(tmp_path)])
    assert main() == 0
    assert list(tmp_path.glob("*.json"))


def test_scanner_export_cli_emits_risk_analyzed_json(tmp_path, monkeypatch, capsys):
    export_path = tmp_path / "finding.json"
    export_path.write_text(
        json.dumps(
            {
                "host": "api.example.test",
                "path": "/api/search",
                "severity": "high",
                "cwe": "CWE-89",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "ctm",
            "--scanner",
            "generic-json",
            "--export",
            str(export_path),
            "--format",
            "json",
        ],
    )

    assert main() == 0

    report = json.loads(capsys.readouterr().out)
    assert report["report"]["finding_count"] == 1
    finding = report["findings"][0]
    assert finding["vulnerability"]["cwe"] == "CWE-89"
    assert finding["score"] > 0
    assert finding["decision"] in {
        "TEST_IMMEDIATELY",
        "PRIORITIZE_VALIDATION",
        "INVESTIGATE",
        "MONITOR",
    }


def test_sarif_report_can_be_written_to_file(tmp_path, monkeypatch):
    output_path = tmp_path / "report.sarif"
    monkeypatch.setattr(
        "sys.argv",
        [
            "ctm",
            "--input-dir",
            "mock_inputs",
            "--format",
            "sarif",
            "--output",
            str(output_path),
        ],
    )

    assert main() == 0

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["version"] == "2.1.0"
    assert report["runs"][0]["results"]
