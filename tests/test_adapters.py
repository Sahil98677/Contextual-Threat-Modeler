import json
from pathlib import Path

from adapters.base import ScannerAdapter
from adapters.generic_json import GenericJSONAdapter
from adapters.nessus import NessusAdapter
from adapters.nmap import NmapAdapter
from adapters.nuclei import NucleiAdapter
from adapters.qualys import QualysCSVAdapter, QualysXMLAdapter
from adapters.registry import get_adapter, list_adapters
from adapters.trivy import TrivyAdapter


def test_all_adapters_implement_contract():
    adapters = [
        GenericJSONAdapter(),
        NmapAdapter(),
        NucleiAdapter(),
        TrivyAdapter(),
        QualysXMLAdapter(),
        QualysCSVAdapter(),
        NessusAdapter(),
    ]
    assert all(isinstance(adapter, ScannerAdapter) for adapter in adapters)


def test_registry_contains_all_adapters():
    assert list_adapters() == [
        "generic-json",
        "nessus",
        "nmap",
        "nuclei",
        "qualys-csv",
        "qualys-xml",
        "trivy",
    ]


def test_registry_returns_adapter_instance():
    assert isinstance(get_adapter("TRIVY"), TrivyAdapter)


def test_generic_json_adapter(tmp_path: Path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"finding": "example"}), encoding="utf-8")
    assert GenericJSONAdapter().parse(path) == [{"finding": "example"}]


def test_nuclei_adapter(tmp_path: Path):
    path = tmp_path / "nuclei.jsonl"
    path.write_text(
        '{"host":"example.test","severity":"high"}\n'
        '{"host":"api.example.test","severity":"medium"}\n',
        encoding="utf-8",
    )
    assert len(NucleiAdapter().parse(path)) == 2


def test_nmap_adapter(tmp_path: Path):
    path = tmp_path / "nmap.xml"
    path.write_text(
        '<nmaprun><host><address addr="10.0.0.1"/>'
        '<ports><port protocol="tcp" portid="443">'
        '<state state="open"/><service name="https"/></port></ports>'
        '</host></nmaprun>',
        encoding="utf-8",
    )
    records = NmapAdapter().parse(path)
    assert records[0]["host"] == "10.0.0.1"
    assert records[0]["port"] == 443


def test_trivy_adapter(tmp_path: Path):
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps({
        "Results": [{
            "Target": "app",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-0001",
                "PkgName": "demo",
                "Severity": "HIGH",
            }],
        }],
    }), encoding="utf-8")
    records = TrivyAdapter().parse(path)
    assert records[0]["vulnerability_id"] == "CVE-2026-0001"
    assert records[0]["severity"] == "HIGH"


def test_qualys_csv_adapter(tmp_path: Path):
    path = tmp_path / "qualys.csv"
    path.write_text(
        "IP,QID,Title,Severity,CVE\n10.0.0.2,1234,Demo,4,CVE-2026-0002\n",
        encoding="utf-8",
    )
    records = QualysCSVAdapter().parse(path)
    assert records[0]["host"] == "10.0.0.2"
    assert records[0]["qid"] == "1234"


def test_qualys_xml_adapter(tmp_path: Path):
    path = tmp_path / "qualys.xml"
    path.write_text(
        '<ROOT><VULN number="1234" severity="4" title="Demo" host="10.0.0.3"/>'
        '</ROOT>',
        encoding="utf-8",
    )
    records = QualysXMLAdapter().parse(path)
    assert records[0]["qid"] == "1234"
    assert records[0]["host"] == "10.0.0.3"


def test_nessus_adapter(tmp_path: Path):
    path = tmp_path / "scan.nessus"
    path.write_text(
        '<NessusClientData_v2><Report><ReportHost name="10.0.0.4">'
        '<ReportItem pluginID="123" pluginName="Demo" severity="3" port="443" protocol="tcp">'
        '<description>Demo issue</description></ReportItem>'
        '</ReportHost></Report></NessusClientData_v2>',
        encoding="utf-8",
    )
    records = NessusAdapter().parse(path)
    assert records[0]["host"] == "10.0.0.4"
    assert records[0]["plugin_id"] == "123"
    assert records[0]["severity"] == 3
