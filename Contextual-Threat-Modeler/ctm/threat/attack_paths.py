from dataclasses import dataclass, asdict


@dataclass
class AttackPath:
    source: str
    entry: str
    weakness: str
    target: str
    impact: str
    path_score: float

    def to_dict(self) -> dict:
        return asdict(self)


def build_attack_paths(finding, asset) -> list[AttackPath]:
    internet = finding.exposure.get("internet_facing", False)
    if not internet:
        return []

    weakness = finding.vulnerability.get("name") or finding.vulnerability.get("cwe") or "unvalidated finding"
    impact = finding.vulnerability.get("impact", "unknown")
    path_score = min(
        100.0,
        finding.score
        + (10 if finding.evidence.get("secret_exposed") else 0)
        + (5 if asset.data_classification in ("confidential", "restricted") else 0),
    )

    return [
        AttackPath(
            source="Internet",
            entry=f"{finding.method} {finding.path}",
            weakness=weakness,
            target=asset.name,
            impact=impact,
            path_score=round(path_score, 1),
        )
    ]
