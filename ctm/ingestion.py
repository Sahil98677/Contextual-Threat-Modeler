import json
from pathlib import Path
from typing import Any

REQUIRED_FILES = {
    "assets": "assets.json",
    "endpoints": "endpoints.json",
    "headers": "header_data.json",
    "secrets": "secrets.json",
    "vulnerabilities": "vulnerabilities.json",
    "controls": "controls.json",
}

VALID_STATUSES = {"discovered", "suspected", "validated", "confirmed"}


def _as_bool(value: Any, default: bool = False) -> bool:
    """Parse common JSON boolean representations without bool('false') pitfalls."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1", "on"}:
            return True
        if normalized in {"false", "no", "n", "0", "off", ""}:
            return False
    return default


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

    asset_ids = set()
    for asset in assets:
        _require(isinstance(asset, dict), "Each asset must be an object.")
        _require(bool(asset.get("id")), "Each asset requires a non-empty id.")
        _require(bool(asset.get("name")), f"Asset {asset.get('id', '<unknown>')} requires a name.")
        if asset["id"] in asset_ids:
            raise ValueError(f"Duplicate asset id: {asset['id']}")
        asset_ids.add(asset["id"])
        criticality = asset.get("criticality", 3)
        _require(isinstance(criticality, (int, float)), f"Invalid criticality for asset {asset['id']}.")
        _require(1 <= criticality <= 5, f"Asset {asset['id']} criticality must be between 1 and 5.")

    endpoint_ids = set()
    endpoint_paths = set()
    for endpoint in endpoints:
        _require(isinstance(endpoint, dict), "Each endpoint must be an object.")
        path = endpoint.get("path")
        _require(bool(path), "Each endpoint requires a non-empty path.")
        endpoint_id = endpoint.get("id")
        if endpoint_id:
            if endpoint_id in endpoint_ids:
                raise ValueError(f"Duplicate endpoint id: {endpoint_id}")
            endpoint_ids.add(endpoint_id)
        if path in endpoint_paths:
            raise ValueError(f"Duplicate endpoint path: {path}")
        endpoint_paths.add(path)

    vulnerabilities = raw["vulnerabilities"]
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities:
            status = vuln.get("status", "discovered")
            _require(
                status in VALID_STATUSES,
                f"Invalid vulnerability status '{status}'. "
                f"Expected one of: {', '.join(sorted(VALID_STATUSES))}.",
            )


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

    def index_by_path(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return {x.get("path") or x.get("url", ""): x for x in items}

    headers = index_by_path(raw["headers"])
    controls = index_by_path(raw["controls"])
    vulnerabilities = index_by_path(raw["vulnerabilities"])
    secrets = index_by_path(raw["secrets"])

    findings = []
    for i, endpoint in enumerate(endpoints, start=1):
        path = endpoint["path"]
        vuln = vulnerabilities.get(path, {})
        header = headers.get(path, {})
        control = controls.get(path, {})
        secret = secrets.get(path)

        findings.append(
            {
                "id": endpoint.get("id", f"F-{i:03d}"),
                "asset_id": endpoint.get("asset_id", "A-001"),
                "method": endpoint.get("method", "GET").upper(),
                "path": path,
                "endpoint_type": endpoint.get("type", "unknown").lower(),
                "exposure": {
                    "internet_facing": _as_bool(endpoint.get("internet_facing", False)),
                    "authentication_required": _as_bool(
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
