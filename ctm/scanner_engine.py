"""Unified scanner-to-CTM execution pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from adapters.registry import parse_export
from .context.asset import build_asset
from .decision.decision_engine import decide
from .models import Finding
from .scanner import normalize_scanner_records
from .scoring.risk import calculate_risk
from .threat.attack_paths import build_correlated_attack_paths
from .threat.mitre import map_mitre
from .threat.stride import map_stride


def run_scanner(
    scanner: str,
    export_path: str | Path,
) -> list[Finding]:
    """Parse one scanner export and run it through the complete CTM engine."""
    records = parse_export(scanner, export_path)
    normalized = normalize_scanner_records(records, scanner)

    assets = {
        key: build_asset(value)
        for key, value in normalized["assets"].items()
    }

    results: list[Finding] = []

    for raw in normalized["findings"]:
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
        results.append(finding)

    correlated_paths = build_correlated_attack_paths(results, assets)
    by_finding = {finding.id: [] for finding in results}
    for path in correlated_paths:
        for finding_id in path.finding_ids:
            by_finding.setdefault(finding_id, []).append(path.to_dict())
    for finding in results:
        finding.attack_paths = by_finding.get(finding.id, [])

    return sorted(results, key=lambda item: item.score, reverse=True)


def run_scanner_dicts(
    scanner: str,
    export_path: str | Path,
) -> list[dict[str, Any]]:
    """Convenience wrapper returning JSON-serializable finding dictionaries."""
    return [finding.to_dict() for finding in run_scanner(scanner, export_path)]
