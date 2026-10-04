from ctm.models import Asset, Finding
from ctm.threat.attack_paths import build_attack_paths


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
