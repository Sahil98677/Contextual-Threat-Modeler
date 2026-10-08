from pathlib import Path

import pytest

from ctm.scanner_engine import run_scanner


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "mock_inputs" / "scanner_samples"


@pytest.mark.parametrize(
    ("scanner", "filename", "expected_count"),
    [
        ("nuclei", "nuclei_sample.jsonl", 2),
        ("trivy", "trivy_sample.json", 1),
        ("nessus", "nessus_sample.nessus", 1),
        ("qualys-csv", "qualys_sample.csv", 1),
    ],
)
def test_synthetic_scanner_reaches_complete_ctm_pipeline(
    scanner: str, filename: str, expected_count: int
):
    findings = run_scanner(scanner, FIXTURES / filename)

    assert len(findings) == expected_count
    assert findings == sorted(findings, key=lambda item: item.score, reverse=True)

    for finding in findings:
        assert finding.asset_id.startswith("SCANNER-")
        assert finding.vulnerability["status"] in {
            "discovered", "suspected", "validated", "confirmed"
        }
        assert 0 <= finding.score <= 100
        assert 0 <= finding.confidence <= 1
        assert 0 <= finding.likelihood <= 10
        assert 0 <= finding.impact <= 10
        assert finding.decision in {
            "TEST_IMMEDIATELY",
            "PRIORITIZE_VALIDATION",
            "INVESTIGATE",
            "MONITOR",
        }
        assert isinstance(finding.threats, list)
        assert isinstance(finding.attack_techniques, list)
        assert isinstance(finding.attack_paths, list)
        assert finding.evidence["source"] == scanner


def test_nuclei_fixture_preserves_high_risk_context():
    findings = run_scanner("nuclei", FIXTURES / "nuclei_sample.jsonl")

    finding = next(item for item in findings if item.path == "/api/users")
    assert finding.vulnerability["cve"] == "CVE-2026-0001"
    assert finding.vulnerability["exploit_available"] is True
    assert finding.vulnerability["attack_complexity"] == "low"
    assert finding.exposure["internet_facing"] is True
    assert finding.exposure["authentication_required"] is False
    assert finding.score >= 85
    assert "T1190" in finding.attack_techniques


def test_trivy_fixture_preserves_dependency_metadata():
    findings = run_scanner("trivy", FIXTURES / "trivy_sample.json")

    finding = findings[0]
    assert finding.vulnerability["vulnerability_id"] == "CVE-2026-0002"
    assert finding.vulnerability["severity"] == "high"
    assert finding.vulnerability["description"]


def test_nessus_fixture_preserves_host_and_service_context():
    findings = run_scanner("nessus", FIXTURES / "nessus_sample.nessus")

    finding = findings[0]
    assert finding.evidence["scanner_record"]["host"] == "10.10.10.20"
    assert finding.path == "https/443"
    assert finding.vulnerability["plugin_id"] == "90001"


def test_qualys_fixture_preserves_qid_and_cve():
    findings = run_scanner("qualys-csv", FIXTURES / "qualys_sample.csv")

    finding = findings[0]
    assert finding.vulnerability["qid"] == "12345"
    assert finding.vulnerability["cve"] == "CVE-2026-0003"


@pytest.mark.parametrize(
    ("scanner", "filename"),
    [
        ("nuclei", "empty.jsonl"),
        ("trivy", "empty.json"),
        ("nessus", "empty.nessus"),
        ("qualys-csv", "empty.csv"),
    ],
)
def test_empty_scanner_exports_produce_no_findings(
    tmp_path: Path, scanner: str, filename: str
):
    path = tmp_path / filename
    if scanner == "nuclei":
        path.write_text("", encoding="utf-8")
    elif scanner == "trivy":
        path.write_text('{"Results": []}', encoding="utf-8")
    elif scanner == "nessus":
        path.write_text(
            '<?xml version="1.0"?><NessusClientData_v2><Report /></NessusClientData_v2>',
            encoding="utf-8",
        )
    else:
        path.write_text("IP,QID,Title,Severity,CVE\n", encoding="utf-8")

    assert run_scanner(scanner, path) == []
