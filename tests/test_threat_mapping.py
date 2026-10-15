from ctm.models import Finding
from ctm.threat.mapping import apply_threat_mappings
from ctm.threat.mitre import map_mitre, mitre_mapping_evidence
from ctm.threat.stride import map_stride, stride_mapping_evidence


def test_stride_mapping_normalizes_known_endpoint_type():
    assert map_stride(" API ") == [
        "Spoofing",
        "Tampering",
        "Information Disclosure",
        "Elevation of Privilege",
    ]


def test_unknown_endpoint_does_not_receive_unsupported_stride_label():
    assert map_stride("unknown") == []
    assert stride_mapping_evidence("unknown") == []


def test_stride_mappings_are_explicitly_inferred_candidates():
    evidence = stride_mapping_evidence("file_upload")

    assert evidence
    assert {item["classification"] for item in evidence} == {"inferred_candidate"}
    assert {item["basis"] for item in evidence} == {"endpoint_type:file_upload"}
    assert all("not evidence" in item["limitation"] for item in evidence)


def test_t1190_candidate_requires_explicit_public_exposure_and_vulnerability():
    vulnerability = {"cve": "CVE-2026-0001"}

    assert map_mitre("api", True, vulnerability) == [
        "T1190 - Exploit Public-Facing Application"
    ]
    assert map_mitre("api", None, vulnerability) == []
    assert map_mitre("api", False, vulnerability) == []
    assert map_mitre("api", True, {}) == []


def test_t1078_candidate_requires_credential_weakness_evidence():
    assert map_mitre("admin", True, {"cwe": "CWE-522"}) == [
        "T1078 - Valid Accounts"
    ]
    assert map_mitre("admin", True, {}) == []
    assert map_mitre("admin", True, {"cwe": "CWE-89"}) == []
    assert map_mitre("admin", False, {"cwe": "CWE-522"}) == []


def test_mitre_mapping_records_rule_basis_and_reference():
    mappings = mitre_mapping_evidence(
        "file_upload",
        True,
        {"cwe": "CWE-434", "exploit_available": True},
    )

    assert mappings == [
        {
            "technique": "T1190 - Exploit Public-Facing Application",
            "classification": "inferred_candidate",
            "basis": [
                "internet_facing:true",
                "endpoint_type:file_upload",
                "cwe:CWE-434",
                "exploit_available:true",
            ],
            "reference": "https://attack.mitre.org/techniques/T1190/",
            "limitation": (
                "Context supports a candidate mapping only; it does not establish "
                "adversary behavior or technique use."
            ),
        }
    ]


def test_pipeline_attaches_traceable_mapping_evidence_to_finding():
    finding = Finding(
        id="F-MAPPING-001",
        asset_id="A-MAPPING-001",
        method="POST",
        path="/upload",
        endpoint_type="file_upload",
        exposure={"internet_facing": True},
        vulnerability={"cwe": "CWE-434", "exploit_available": True},
    )

    apply_threat_mappings(finding)

    assert "Tampering" in finding.threats
    assert finding.attack_techniques == [
        "T1190 - Exploit Public-Facing Application"
    ]
    evidence = finding.evidence["threat_mapping_evidence"]
    assert evidence["stride"] == stride_mapping_evidence("file_upload")
    assert evidence["mitre_attack"] == mitre_mapping_evidence(
        "file_upload",
        True,
        finding.vulnerability,
    )
