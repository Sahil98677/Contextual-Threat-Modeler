from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Asset:
    id: str
    name: str
    asset_type: str = "web_application"
    criticality: int = 3
    data_classification: str = "internal"
    production: bool = True
    owner: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    asset_id: str
    method: str
    path: str
    endpoint_type: str
    exposure: dict[str, Any] = field(default_factory=dict)
    vulnerability: dict[str, Any] = field(default_factory=dict)
    controls: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    threats: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    score: float = 0.0
    confidence: float = 0.0
    likelihood: float = 0.0
    impact: float = 0.0
    decision: str = "MONITOR"
    rationale: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
