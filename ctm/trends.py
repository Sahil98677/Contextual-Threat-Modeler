"""Historical risk snapshots and posture trend analysis."""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class AssetSnapshot:
    asset_id: str
    finding_count: int
    max_score: float
    average_score: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


@dataclass(frozen=True)
class RiskSnapshot:
    timestamp: str
    finding_count: int
    average_score: float
    highest_score: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    assets: list[AssetSnapshot]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _risk_bucket(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def create_snapshot(results: Iterable[Any], timestamp: str | None = None) -> RiskSnapshot:
    results = list(results)
    scores = [float(item.score) for item in results]
    counts = {name: 0 for name in ("critical", "high", "medium", "low")}
    grouped: dict[str, list[Any]] = {}

    for finding in results:
        counts[_risk_bucket(float(finding.score))] += 1
        grouped.setdefault(finding.asset_id, []).append(finding)

    assets = []
    for asset_id, findings in sorted(grouped.items()):
        asset_scores = [float(item.score) for item in findings]
        asset_counts = {name: 0 for name in counts}
        for score in asset_scores:
            asset_counts[_risk_bucket(score)] += 1
        assets.append(AssetSnapshot(
            asset_id=asset_id,
            finding_count=len(findings),
            max_score=round(max(asset_scores), 1),
            average_score=round(sum(asset_scores) / len(asset_scores), 1),
            critical_count=asset_counts["critical"],
            high_count=asset_counts["high"],
            medium_count=asset_counts["medium"],
            low_count=asset_counts["low"],
        ))

    ts = timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return RiskSnapshot(
        timestamp=ts,
        finding_count=len(results),
        average_score=round(sum(scores) / len(scores), 1) if scores else 0.0,
        highest_score=round(max(scores), 1) if scores else 0.0,
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        assets=assets,
    )


def save_snapshot(snapshot: RiskSnapshot, history_dir: str | Path) -> Path:
    directory = Path(history_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = snapshot.timestamp.replace(":", "").replace("-", "")
    filename = f"{stamp}.json"
    path = directory / filename
    if path.exists():
        index = 2
        while (directory / f"{stamp}-{index}.json").exists():
            index += 1
        path = directory / f"{stamp}-{index}.json"
    path.write_text(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_snapshots(history_dir: str | Path) -> list[RiskSnapshot]:
    directory = Path(history_dir)
    if not directory.exists():
        return []
    snapshots = []
    for path in sorted(directory.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        snapshots.append(RiskSnapshot(
            timestamp=payload["timestamp"],
            finding_count=int(payload["finding_count"]),
            average_score=float(payload["average_score"]),
            highest_score=float(payload["highest_score"]),
            critical_count=int(payload["critical_count"]),
            high_count=int(payload["high_count"]),
            medium_count=int(payload["medium_count"]),
            low_count=int(payload["low_count"]),
            assets=[AssetSnapshot(**item) for item in payload.get("assets", [])],
        ))
    return sorted(snapshots, key=lambda item: item.timestamp)


def compare_snapshots(current: RiskSnapshot, previous: RiskSnapshot | None) -> dict[str, Any]:
    if previous is None:
        return {"available": False, "status": "BASELINE", "message": "No previous snapshot available."}

    delta = round(current.average_score - previous.average_score, 1)
    if delta < -0.1:
        status = "IMPROVING"
    elif delta > 0.1:
        status = "DEGRADING"
    else:
        status = "STABLE"

    previous_assets = {item.asset_id: item for item in previous.assets}
    assets = []
    for item in current.assets:
        old = previous_assets.get(item.asset_id)
        if old is None:
            assets.append({"asset_id": item.asset_id, "status": "NEW", "delta": None})
            continue
        asset_delta = round(item.max_score - old.max_score, 1)
        asset_status = "IMPROVING" if asset_delta < -0.1 else "DEGRADING" if asset_delta > 0.1 else "STABLE"
        assets.append({"asset_id": item.asset_id, "status": asset_status, "delta": asset_delta})

    return {
        "available": True,
        "status": status,
        "average_score_delta": delta,
        "previous_timestamp": previous.timestamp,
        "current_timestamp": current.timestamp,
        "assets": assets,
    }


def build_trend(results: Iterable[Any], history_dir: str | Path) -> tuple[RiskSnapshot, dict[str, Any], Path]:
    previous = load_snapshots(history_dir)
    current = create_snapshot(results)
    comparison = compare_snapshots(current, previous[-1] if previous else None)
    path = save_snapshot(current, history_dir)
    return current, comparison, path
