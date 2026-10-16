import pytest

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
    assert paths[0].classification == "inferred_candidate"
    assert paths[0].confirmed is False
    assert paths[0].evidence["internet_facing_finding_ids"] == ["F"]
    assert paths[0].limitations


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
    assert "unordered" in paths[0].nodes[2]
    assert paths[0].confirmed is False
    assert paths[0].classification == "inferred_candidate"
    assert paths[0].evidence["correlated_finding_ids"] == ["F1", "F2"]
    assert "No exploitability" in " ".join(paths[0].limitations)
    assert paths[0].path_score == 90.0
    assert paths[0].evidence["path_score_basis"] == {
        "maximum_finding_score": 80,
        "correlation_increment": 5.0,
        "sensitive_data_increment": 5.0,
    }


def test_correlated_path_score_is_capped_at_100() -> None:
    findings = [
        Finding(
            id=f"F{index}",
            asset_id="A",
            method="GET",
            path=f"/endpoint-{index}",
            endpoint_type="api",
            exposure={"internet_facing": index == 1},
            score=85 if index == 1 else 60,
        )
        for index in range(1, 6)
    ]
    asset = Asset(
        id="A",
        name="Portal",
        criticality=5,
        data_classification="restricted",
    )

    path = build_correlated_attack_paths(findings, {"A": asset})[0]

    assert path.path_score == 100.0
    assert 0.0 <= path.path_score <= 100.0
    assert path.evidence["path_score_basis"] == {
        "maximum_finding_score": 85,
        "correlation_increment": 15.0,
        "sensitive_data_increment": 5.0,
    }


def test_correlations_and_identifiers_are_deterministic():
    findings = [
        Finding(
            id="Z-EXTERNAL",
            asset_id="Z",
            method="GET",
            path="/public",
            endpoint_type="api",
            exposure={"internet_facing": True},
            score=80,
        ),
        Finding(
            id="A-EXTERNAL",
            asset_id="A",
            method="GET",
            path="/public",
            endpoint_type="api",
            exposure={"internet_facing": True},
            score=80,
        ),
        Finding(
            id="A-INTERNAL",
            asset_id="A",
            method="GET",
            path="/admin",
            endpoint_type="api",
            exposure={"internet_facing": False},
            score=70,
        ),
    ]
    assets = {
        "Z": Asset(id="Z", name="Zulu", criticality=3),
        "A": Asset(id="A", name="Alpha", criticality=3),
    }

    first = build_correlated_attack_paths(findings, assets)
    second = build_correlated_attack_paths(list(reversed(findings)), assets)

    assert [path.to_dict() for path in first] == [
        path.to_dict() for path in second
    ]
    assert [(path.path_id, path.finding_ids) for path in first] == [
        ("PATH-001", ["A-EXTERNAL", "A-INTERNAL"]),
        ("PATH-002", ["Z-EXTERNAL"]),
    ]


@pytest.mark.parametrize("exposure", [None, "true", 1])
def test_non_boolean_exposure_does_not_create_candidate_path(exposure):
    finding = Finding(
        id="F",
        asset_id="A",
        method="GET",
        path="/x",
        endpoint_type="api",
        exposure={"internet_facing": exposure},
    )
    asset = Asset(id="A", name="Portal", criticality=3)

    assert build_attack_paths(finding, asset) == []
    assert build_correlated_attack_paths([finding], {"A": asset}) == []


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
