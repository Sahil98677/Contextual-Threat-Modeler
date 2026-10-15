import json
from pathlib import Path

import pytest

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


def test_nuclei_adapter_rejects_malformed_jsonl(tmp_path: Path):
    path = tmp_path / "nuclei-bad.jsonl"
    path.write_text(
        '{"host":"example.test","severity":"high"}\n'
        '{"host": "broken"\n',
        encoding="utf-8",
    )
    try:
        NucleiAdapter().parse(path)
        raise AssertionError("Expected malformed JSONL to raise ValueError")
    except ValueError:
        pass


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


def test_nmap_adapter_ignores_malformed_ports_and_accepts_open_filtered(tmp_path: Path):
    path = tmp_path / "nmap-mixed.xml"
    path.write_text(
        '<nmaprun><host><address addr="10.0.0.2"/>'
        '<ports>'
        '<port protocol="tcp" portid="not-a-number"><state state="open"/></port>'
        '<port protocol="tcp" portid="80"><state state="open|filtered"/>'
        '<service name="http"/></port>'
        '<port protocol="udp" portid="53"><state state="closed"/></port>'
        '</ports></host></nmaprun>',
        encoding="utf-8",
    )
    records = NmapAdapter().parse(path)
    assert len(records) == 1
    assert records[0]["host"] == "10.0.0.2"
    assert records[0]["port"] == 80
    assert records[0]["service"] == "http"


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


def test_trivy_adapter_ignores_malformed_cvss_metadata(tmp_path: Path):
    path = tmp_path / "trivy-malformed-cvss.json"
    path.write_text(json.dumps({
        "Results": [{
            "Target": "app",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-0001",
                    "CVSS": "invalid",
                },
                {
                    "VulnerabilityID": "CVE-2026-0002",
                    "CVSS": {"nvd": "invalid"},
                },
                {
                    "VulnerabilityID": "CVE-2026-0003",
                    "CVSS": {"nvd": {"V3Score": "not-a-number"}},
                },
                {
                    "VulnerabilityID": "CVE-2026-0004",
                    "CVSS": {"nvd": {"V3Score": 11}},
                },
            ],
        }],
    }), encoding="utf-8")

    records = TrivyAdapter().parse(path)

    assert len(records) == 4
    assert all(record["cvss_v3"] is None for record in records)


def test_trivy_adapter_preserves_valid_cvss_score(tmp_path: Path):
    path = tmp_path / "trivy-valid-cvss.json"
    path.write_text(json.dumps({
        "Results": [{
            "Target": "app",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-0005",
                "CVSS": {"nvd": {"V3Score": 9.8}},
            }],
        }],
    }), encoding="utf-8")

    records = TrivyAdapter().parse(path)

    assert records[0]["cvss_v3"] == 9.8


@pytest.mark.parametrize(
    "results",
    [
        "",
        {},
        "invalid",
    ],
)
def test_trivy_adapter_rejects_malformed_results(tmp_path: Path, results):
    path = tmp_path / "trivy-invalid-results.json"
    path.write_text(
        json.dumps({"Results": results}),
        encoding="utf-8",
    )

    with pytest.raises(TypeError, match="Trivy Results"):
        TrivyAdapter().parse(path)


@pytest.mark.parametrize("vulnerabilities", ["", {}, "invalid"])
def test_trivy_adapter_rejects_malformed_vulnerabilities(
    tmp_path: Path,
    vulnerabilities,
):
    path = tmp_path / "trivy-invalid-vulnerabilities.json"
    path.write_text(
        json.dumps({
            "Results": [{
                "Target": "app",
                "Vulnerabilities": vulnerabilities,
            }],
        }),
        encoding="utf-8",
    )

    with pytest.raises(TypeError, match="Trivy vulnerabilities"):
        TrivyAdapter().parse(path)


def test_trivy_adapter_normalizes_malformed_references(tmp_path: Path):
    path = tmp_path / "trivy-invalid-references.json"
    path.write_text(
        json.dumps({
            "Results": [{
                "Target": "app",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0006",
                        "References": "not-a-list",
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0007",
                        "References": ["https://example.test/advisory", 42],
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0008",
                        "References": [
                            "https://example.test/valid-advisory",
                        ],
                    },
                ],
            }],
        }),
        encoding="utf-8",
    )

    records = TrivyAdapter().parse(path)

    assert records[0]["references"] == []
    assert records[1]["references"] == []
    assert records[2]["references"] == [
        "https://example.test/valid-advisory",
    ]


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
