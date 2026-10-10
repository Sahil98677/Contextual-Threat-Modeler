import json
import math
from pathlib import Path
from typing import Any

from .context.values import as_bool

REQUIRED_FILES = {
    "assets": "assets.json",
    "endpoints": "endpoints.json",
    "headers": "header_data.json",
    "secrets": "secrets.json",
    "vulnerabilities": "vulnerabilities.json",
    "controls": "controls.json",
}

VALID_STATUSES = {"discovered", "suspected", "validated", "confirmed"}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_inputs(raw: dict[str, Any]) -> None:
    _require(isinstance(raw, dict), "CTM input must be a JSON object.")
    missing = [key for key in REQUIRED_FILES if key not in raw]
    _require(not missing, f"Missing top-level input sections: {', '.join(missing)}")

    assets = raw["assets"]
    endpoints = raw["endpoints"]
    _require(isinstance(assets, list), "assets must be a JSON array.")
    _require(isinstance(endpoints, list), "endpoints must be a JSON array.")
    for section in ("headers", "secrets", "vulnerabilities", "controls"):
        _require(isinstance(raw[section], list), f"{section} must be a JSON array.")

    asset_ids = set()
    for asset in assets:
        _require(isinstance(asset, dict), "Each asset must be an object.")
        _require(
            isinstance(asset.get("id"), str) and bool(asset["id"].strip()),
            "Each asset requires a non-empty string id.",
        )
        _require(
            isinstance(asset.get("name"), str) and bool(asset["name"].strip()),
            f"Asset {asset.get('id', '<unknown>')} requires a non-empty name.",
        )
        for field in ("asset_type", "data_classification", "owner"):
            _require(
                field not in asset or isinstance(asset[field], str),
                f"Asset {asset['id']} field {field} must be a string.",
            )
        _require(
            "tags" not in asset
            or isinstance(asset["tags"], list)
            and all(isinstance(tag, str) for tag in asset["tags"]),
            f"Asset {asset['id']} tags must be an array of strings.",
        )
        if asset["id"] in asset_ids:
            raise ValueError(f"Duplicate asset id: {asset['id']}")
        asset_ids.add(asset["id"])
        criticality = asset.get("criticality", 3)
        _require(
            isinstance(criticality, (int, float))
            and not isinstance(criticality, bool)
            and math.isfinite(criticality),
            f"Invalid criticality for asset {asset['id']}.",
        )
        _require(
            1 <= criticality <= 5,
            f"Asset {asset['id']} criticality must be between 1 and 5.",
        )
    known_asset_ids = asset_ids

    endpoint_ids = set()
    endpoint_paths = set()
    for endpoint in endpoints:
        _require(isinstance(endpoint, dict), "Each endpoint must be an object.")
        path = endpoint.get("path")
        _require(
            isinstance(path, str) and bool(path.strip()),
            "Each endpoint requires a non-empty string path.",
        )
        if "id" in endpoint:
            endpoint_id = endpoint["id"]
            _require(
                isinstance(endpoint_id, str) and bool(endpoint_id.strip()),
                "Endpoint id must be a non-empty string.",
            )
            if endpoint_id in endpoint_ids:
                raise ValueError(f"Duplicate endpoint id: {endpoint_id}")
            endpoint_ids.add(endpoint_id)
        for field in ("method", "type"):
            _require(
                field not in endpoint or isinstance(endpoint[field], str),
                f"Endpoint {field} must be a string.",
            )
        if "asset_id" in endpoint:
            _require(
                isinstance(endpoint["asset_id"], str)
                and endpoint["asset_id"] in known_asset_ids,
                f"Endpoint {endpoint.get('id', path)} references an unknown asset.",
            )
        if path in endpoint_paths:
            raise ValueError(f"Duplicate endpoint path: {path}")
        endpoint_paths.add(path)

    vulnerabilities = raw["vulnerabilities"]
    for section in ("headers", "secrets", "vulnerabilities", "controls"):
        _require(
            all(isinstance(item, dict) for item in raw[section]),
            f"Each {section} entry must be an object.",
        )
        for item in raw[section]:
            for key in ("path", "url"):
                _require(
                    key not in item or isinstance(item[key], str),
                    f"{section} entry {key} must be a string.",
                )
            path = item.get("path") or item.get("url")
            _require(
                isinstance(path, str) and bool(path.strip()),
                f"Each {section} entry requires a non-empty path or url.",
            )
    for vuln in vulnerabilities:
        status = vuln.get("status", "discovered")
        _require(
            isinstance(status, str) and status in VALID_STATUSES,
            f"Invalid vulnerability status '{status}'. "
            f"Expected one of: {', '.join(sorted(VALID_STATUSES))}.",
        )

    endpoint_paths = {endpoint["path"] for endpoint in endpoints}
    for section in ("headers", "secrets", "vulnerabilities", "controls"):
        seen_paths = set()
        for item in raw[section]:
            path = item.get("path") or item.get("url")
            _require(
                path in endpoint_paths,
                f"{section} entry references an unknown endpoint: {path}",
            )
            if section != "vulnerabilities":
                _require(
                    path not in seen_paths,
                    f"Duplicate {section} entry for endpoint: {path}",
                )
            seen_paths.add(path)


def load_inputs(input_dir: str = "mock_inputs") -> dict[str, Any]:
    root = Path(input_dir)
    missing = [name for name in REQUIRED_FILES.values() if not (root / name).exists()]
    if missing:
        raise FileNotFoundError(
            f"Missing input files in {root}: {', '.join(missing)}"
        )
    raw = {key: load_json(root / filename) for key, filename in REQUIRED_FILES.items()}
    validate_inputs(raw)
    return raw


def normalize(raw: dict[str, Any]) -> dict[str, Any]:
    validate_inputs(raw)
    assets = {x["id"]: x for x in raw["assets"]}
    endpoints = raw["endpoints"]
    default_asset_id = next(iter(assets), "")

    def index_by_path(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return {x.get("path") or x.get("url", ""): x for x in items}

    def group_by_path(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in items:
            path = item.get("path") or item.get("url", "")
            grouped.setdefault(path, []).append(item)
        return grouped

    headers = index_by_path(raw["headers"])
    controls = index_by_path(raw["controls"])
    vulnerabilities = group_by_path(raw["vulnerabilities"])
    secrets = index_by_path(raw["secrets"])

    findings = []
    for i, endpoint in enumerate(endpoints, start=1):
        path = endpoint["path"]
        vulns = vulnerabilities.get(path) or [{}]
        header = headers.get(path, {})
        control = controls.get(path, {})
        secret = secrets.get(path)

        for vuln_index, raw_vuln in enumerate(vulns, start=1):
            vuln = dict(raw_vuln)
            if "exploit_available" in vuln:
                vuln["exploit_available"] = as_bool(vuln["exploit_available"])
            for field in ("impact", "attack_complexity"):
                if isinstance(vuln.get(field), str):
                    vuln[field] = vuln[field].strip().lower()

            finding_id = endpoint.get("id", f"F-{i:03d}")
            if len(vulns) > 1:
                finding_id = f"{finding_id}-V{vuln_index:02d}"
            findings.append(
                {
                    "id": finding_id,
                    "asset_id": endpoint.get("asset_id", default_asset_id),
                    "method": endpoint.get("method", "GET").upper(),
                    "path": path,
                    "endpoint_type": endpoint.get("type", "unknown").lower(),
                    "exposure": {
                        "internet_facing": as_bool(endpoint.get("internet_facing", False)),
                        "authentication_required": as_bool(
                            endpoint.get("authentication_required", True), True
                        ),
                        "trust_zone": endpoint.get("trust_zone", "internal"),
                    },
                    "vulnerability": {
                        **vuln,
                        "status": vuln.get("status", "discovered"),
                    },
                    "controls": {
                        **control,
                        "security_headers": header.get("security_policy", "unknown"),
                    },
                    "evidence": {
                        "source": endpoint.get("source", "recon"),
                        "details": endpoint.get("details", ""),
                        "secret_exposed": bool(secret),
                        "secret_type": secret.get("secret_type") if secret else None,
                    },
                }
            )

    return {"assets": assets, "findings": findings}
