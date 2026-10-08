from pathlib import Path

from ctm.models import Finding
from ctm.trends import compare_snapshots, create_snapshot, load_snapshots, save_snapshot


def finding(fid, asset, score):
    return Finding(id=fid, asset_id=asset, method="GET", path=f"/{fid}", endpoint_type="api", score=score)


def test_snapshot_aggregates_risk_by_asset():
    snapshot = create_snapshot([
        finding("F1", "A", 90),
        finding("F2", "A", 70),
        finding("F3", "B", 40),
    ], timestamp="2026-10-08T10:00:00Z")
    assert snapshot.finding_count == 3
    assert snapshot.average_score == 66.7
    assert snapshot.highest_score == 90.0
    assert snapshot.critical_count == 1
    assert snapshot.high_count == 1
    assert snapshot.medium_count == 0
    assert snapshot.low_count == 1
    assert snapshot.assets[0].asset_id == "A"
    assert snapshot.assets[0].max_score == 90.0


def test_snapshot_round_trip(tmp_path: Path):
    snapshot = create_snapshot([finding("F1", "A", 80)], timestamp="2026-10-08T10:00:00Z")
    save_snapshot(snapshot, tmp_path)
    loaded = load_snapshots(tmp_path)
    assert len(loaded) == 1
    assert loaded[0].to_dict() == snapshot.to_dict()


def test_comparison_reports_improvement():
    previous = create_snapshot([finding("F1", "A", 90)], timestamp="2026-10-07T10:00:00Z")
    current = create_snapshot([finding("F1", "A", 60)], timestamp="2026-10-08T10:00:00Z")
    trend = compare_snapshots(current, previous)
    assert trend["status"] == "IMPROVING"
    assert trend["average_score_delta"] == -30.0
    assert trend["assets"][0]["status"] == "IMPROVING"


def test_comparison_reports_degradation():
    previous = create_snapshot([finding("F1", "A", 50)], timestamp="2026-10-07T10:00:00Z")
    current = create_snapshot([finding("F1", "A", 80)], timestamp="2026-10-08T10:00:00Z")
    trend = compare_snapshots(current, previous)
    assert trend["status"] == "DEGRADING"
    assert trend["average_score_delta"] == 30.0


def test_comparison_without_baseline():
    current = create_snapshot([], timestamp="2026-10-08T10:00:00Z")
    trend = compare_snapshots(current, None)
    assert trend["status"] == "BASELINE"
    assert trend["available"] is False
