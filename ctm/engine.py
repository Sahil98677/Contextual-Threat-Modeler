from .context.asset import build_asset
from .decision.decision_engine import decide
from .ingestion import load_inputs, normalize
from .models import Finding
from .scoring.risk import calculate_risk
from .threat.attack_paths import build_attack_paths
from .threat.mitre import map_mitre
from .threat.stride import map_stride


def run(input_dir: str = "mock_inputs"):
    data = normalize(load_inputs(input_dir))
    assets = {key: build_asset(value) for key, value in data["assets"].items()}

    results = []
    for raw in data["findings"]:
        finding = Finding(**raw)
        asset = assets.get(
            finding.asset_id,
            build_asset({"id": finding.asset_id, "name": finding.asset_id}),
        )

        finding.threats = map_stride(finding.endpoint_type)
        finding.attack_techniques = map_mitre(
            finding.endpoint_type,
            finding.exposure.get("internet_facing", False),
            finding.vulnerability,
        )

        calculate_risk(finding, asset)
        finding.decision = decide(finding.score, finding.confidence)

        finding.attack_paths = [
            path.to_dict() for path in build_attack_paths(finding, asset)
        ]
        results.append(finding)

    return sorted(results, key=lambda item: item.score, reverse=True)
