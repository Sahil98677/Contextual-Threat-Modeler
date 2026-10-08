from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AttackPath:
    source: str
    entry: str
    weakness: str
    target: str
    impact: str
    path_score: float
    path_id: str = "PATH-001"
    nodes: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    relationship: str = "candidate"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _single_path(finding, asset, path_id: str = "PATH-001") -> AttackPath | None:
    if not finding.exposure.get("internet_facing", False):
        return None

    weakness = (
        finding.vulnerability.get("name")
        or finding.vulnerability.get("title")
        or finding.vulnerability.get("cwe")
        or "unvalidated finding"
    )
    impact = finding.vulnerability.get("impact", "unknown")
    path_score = min(
        100.0,
        finding.score
        + (10 if finding.evidence.get("secret_exposed") else 0)
        + (5 if asset.data_classification in ("confidential", "restricted") else 0),
    )
    entry = f"{finding.method} {finding.path}"
    nodes = ["Internet", entry, weakness, asset.name]
    return AttackPath(
        source="Internet", entry=entry, weakness=weakness, target=asset.name,
        impact=impact, path_score=round(path_score, 1), path_id=path_id,
        nodes=nodes, finding_ids=[finding.id],
    )


def build_attack_paths(finding, asset) -> list[AttackPath]:
    path = _single_path(finding, asset)
    return [path] if path else []


def build_correlated_attack_paths(findings, assets) -> list[AttackPath]:
    """Build conservative candidate paths across related findings.

    Findings are correlated only when they belong to the same asset and at
    least one finding is internet-facing. CTM does not claim exploitability
    between findings unless the input data establishes that relationship.
    """
    grouped: dict[str, list[Any]] = {}
    for finding in findings:
        grouped.setdefault(finding.asset_id, []).append(finding)

    paths: list[AttackPath] = []
    for asset_id, related in grouped.items():
        asset = assets.get(asset_id)
        if asset is None:
            continue
        external = [item for item in related if item.exposure.get("internet_facing", False)]
        if not external:
            continue

        ordered = sorted(related, key=lambda item: item.score, reverse=True)
        entry = external[0]
        path_id = f"PATH-{len(paths) + 1:03d}"
        nodes = ["Internet", f"{entry.method} {entry.path}"]
        finding_ids = [entry.id]
        for item in ordered:
            if item.id == entry.id:
                continue
            nodes.append(f"{item.method} {item.path}")
            finding_ids.append(item.id)
        nodes.append(asset.name)

        path_score = min(
            100.0,
            max(item.score for item in ordered)
            + min(15.0, 5.0 * (len(ordered) - 1))
            + (5.0 if asset.data_classification in ("confidential", "restricted") else 0.0),
        )
        weakness = (
            entry.vulnerability.get("name")
            or entry.vulnerability.get("title")
            or entry.vulnerability.get("cwe")
            or "correlated scanner findings"
        )
        impacts = [str(item.vulnerability.get("impact")) for item in ordered if item.vulnerability.get("impact")]
        impact = max(
            impacts,
            key=lambda value: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(value.lower(), 0),
            default="unknown",
        )
        paths.append(AttackPath(
            source="Internet", entry=f"{entry.method} {entry.path}", weakness=weakness,
            target=asset.name, impact=impact, path_score=round(path_score, 1),
            path_id=path_id, nodes=nodes, finding_ids=finding_ids,
            relationship="same-asset candidate correlation",
        ))
    return sorted(paths, key=lambda path: path.path_score, reverse=True)
