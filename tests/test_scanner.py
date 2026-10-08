from pathlib import Path
from adapters.registry import list_adapters, parse_export
from ctm.scanner import normalize_scanner_records

def test_registry_contains_all_scanner_adapters():
    adapters = list_adapters()
    assert {"generic-json", "nmap", "nuclei", "trivy", "qualys-xml", "qualys-csv", "nessus"} <= set(adapters)

def test_scanner_record_becomes_ctm_finding():
    data = normalize_scanner_records([{
        "host": "api.example.test",
        "path": "/api/users",
        "service": "https",
        "severity": "high",
        "cve": "CVE-2026-0001",
        "internet_facing": True,
    }], "nuclei")
    finding = data["findings"][0]
    assert len(data["assets"]) == 1
    assert finding["path"] == "/api/users"
    assert finding["vulnerability"]["status"] == "validated"
    assert finding["vulnerability"]["cve"] == "CVE-2026-0001"
    assert finding["exposure"]["internet_facing"] is True

def test_parse_export_always_returns_list(tmp_path: Path):
    path = tmp_path / "generic.json"
    path.write_text('{"finding": "example"}', encoding="utf-8")
    assert parse_export("generic-json", path) == [{"finding": "example"}]
