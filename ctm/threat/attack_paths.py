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
    classification: str = "inferred_candidate"
    confirmed: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _single_path(finding, asset, path_id: str = "PATH-001") -> AttackPath | None:
    if finding.exposure.get("internet_facing") is not True:
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
    nodes = ["Internet-facing exposure", entry, weakness, asset.name]
    return AttackPath(
        source="Internet", entry=entry, weakness=weakness, target=asset.name,
        impact=impact, path_score=round(path_score, 1), path_id=path_id,
        nodes=nodes,
        finding_ids=[finding.id],
        relationship="single finding with explicit internet-facing exposure",
        evidence={
            "asset_id": finding.asset_id,
            "internet_facing_finding_ids": [finding.id],
            "correlation_basis": "explicit internet_facing=true on finding",
            "path_score_basis": {
                "finding_score": finding.score,
                "secret_exposure_increment": (
                    10.0 if finding.evidence.get("secret_exposed") else 0.0
                ),
                "sensitive_data_increment": (
                    5.0
                    if asset.data_classification
                    in ("confidential", "restricted")
                    else 0.0
                ),
            },
        },
        limitations=[
            "Candidate path only; no exploitability or successful access is confirmed.",
            "No network, trust-boundary, or control-bypass relationship was established.",
        ],
    )


def build_attack_paths(finding, asset) -> list[AttackPath]:
    path = _single_path(finding, asset)
    return [path] if path else []


def build_correlated_attack_paths(findings, assets) -> list[AttackPath]:
    """Build deterministic same-asset candidate correlations, not attack chains.

    Findings are correlated only when they belong to the same asset and at
    least one finding explicitly declares internet-facing exposure. The set is
    unordered: this function has no evidence that one finding enables another.
    """
    grouped: dict[str, list[Any]] = {}
    for finding in findings:
        grouped.setdefault(finding.asset_id, []).append(finding)

    paths: list[AttackPath] = []
    for asset_id in sorted(grouped):
        related = grouped[asset_id]
        asset = assets.get(asset_id)
        if asset is None:
            continue
        external = [
            item
            for item in related
            if item.exposure.get("internet_facing") is True
        ]
        if not external:
            continue

        ordered = sorted(related, key=lambda item: item.id)
        entry = min(external, key=lambda item: item.id)
        path_id = f"PATH-{len(paths) + 1:03d}"
        finding_ids = [item.id for item in ordered]
        nodes = [
            "Internet-facing exposure",
            f"{entry.method} {entry.path}",
            f"Same-asset finding set (unordered): {', '.join(finding_ids)}",
            asset.name,
        ]

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
        impacts = [
            str(item.vulnerability.get("impact"))
            for item in ordered
            if item.vulnerability.get("impact")
        ]
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
            evidence={
                "asset_id": asset_id,
                "internet_facing_finding_ids": sorted(item.id for item in external),
                "correlated_finding_ids": finding_ids,
                "correlation_basis": (
                    "shared asset_id and explicit internet_facing=true "
                    "on at least one finding"
                ),
                "path_score_basis": {
                    "maximum_finding_score": max(item.score for item in ordered),
                    "correlation_increment": min(
                        15.0,
                        5.0 * (len(ordered) - 1),
                    ),
                    "sensitive_data_increment": (
                        5.0
                        if asset.data_classification
                        in ("confidential", "restricted")
                        else 0.0
                    ),
                },
            },
            limitations=[
                "Candidate correlation only; findings are not ordered as an attack chain.",
                "No exploitability or successful access between findings is established.",
                "Network reachability, trust boundaries, and control bypasses are not modeled.",
            ],
        ))
    return sorted(paths, key=lambda path: path.path_score, reverse=True)
