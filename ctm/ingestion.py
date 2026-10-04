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


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_inputs(input_dir: str = "mock_inputs") -> dict[str, Any]:
    root = Path(input_dir)
    missing = [name for name in REQUIRED_FILES.values() if not (root / name).exists()]
    if missing:
        raise FileNotFoundError(
            f"Missing input files in {root}: {', '.join(missing)}"
        )
    return {key: load_json(root / filename) for key, filename in REQUIRED_FILES.items()}


def normalize(raw: dict[str, Any]) -> dict[str, Any]:
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
                    "internet_facing": bool(endpoint.get("internet_facing", False)),
                    "authentication_required": bool(
                        endpoint.get("authentication_required", True)
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
