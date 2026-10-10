from ctm.models import Asset, Finding
from ctm.threat.attack_paths import build_attack_paths, build_correlated_attack_paths


def test_internet_facing_finding_creates_path():
    finding = Finding(
        id="F",
        asset_id="A",
        method="POST",
        path="/upload",
        endpoint_type="file_upload",
        exposure={"internet_facing": True},
        vulnerability={"name": "Upload issue"},
        score=80,
    )
    asset = Asset(id="A", name="Portal", criticality=5)
    paths = build_attack_paths(finding, asset)
    assert len(paths) == 1
    assert paths[0].source == "Internet"


def test_internal_finding_has_no_external_path():
    finding = Finding(
        id="F",
        asset_id="A",
        method="GET",
        path="/x",
        endpoint_type="api",
        exposure={"internet_facing": False},
    )
    asset = Asset(id="A", name="Internal", criticality=3)
    assert build_attack_paths(finding, asset) == []


def test_same_asset_findings_are_correlated():
    findings = [
        Finding(
            id="F1",
            asset_id="A",
            method="GET",
            path="/api/users",
            endpoint_type="api",
            exposure={"internet_facing": True},
            vulnerability={"title": "Public API issue", "impact": "high"},
            score=80,
        ),
        Finding(
            id="F2",
            asset_id="A",
            method="GET",
            path="/admin",
            endpoint_type="admin",
            exposure={"internet_facing": False},
            vulnerability={"title": "Admin weakness", "impact": "critical"},
            score=70,
        ),
    ]
    asset = Asset(
        id="A",
        name="Portal",
        criticality=5,
        data_classification="restricted",
    )
    paths = build_correlated_attack_paths(findings, {"A": asset})
    assert len(paths) == 1
    assert paths[0].path_id == "PATH-001"
    assert paths[0].finding_ids == ["F1", "F2"]
    assert paths[0].nodes[-1] == "Portal"


def test_same_asset_internal_only_findings_have_no_path():
    finding = Finding(
        id="F",
        asset_id="A",
        method="GET",
        path="/internal",
        endpoint_type="api",
        exposure={"internet_facing": False},
        score=70,
    )
    asset = Asset(id="A", name="Internal", criticality=3)
    assert build_correlated_attack_paths([finding], {"A": asset}) == []
