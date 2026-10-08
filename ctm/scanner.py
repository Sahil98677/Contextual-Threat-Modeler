"""Map scanner adapter records into CTM Finding-compatible data."""
from __future__ import annotations
from typing import Any
from .models import Asset, Finding

VALID_STATUSES = {"discovered", "suspected", "validated", "confirmed"}
SEVERITY_STATUS = {
    "critical": "confirmed",
    "high": "validated",
    "medium": "suspected",
    "low": "discovered",
    "info": "discovered",
    "informational": "discovered",
}

def _status(record: dict[str, Any]) -> str:
    explicit = str(record.get("status", "")).strip().lower()
    if explicit in VALID_STATUSES:
        return explicit
    return SEVERITY_STATUS.get(str(record.get("severity", "")).strip().lower(), "discovered")

def _target(record: dict[str, Any]) -> str:
    return str(record.get("target") or record.get("host") or record.get("ip") or record.get("asset") or "unknown")

def _path(record: dict[str, Any], index: int) -> str:
    path = record.get("path") or record.get("url")
    if path:
        return str(path)
    if record.get("port"):
        return f"{record.get('service') or 'tcp'}/{record['port']}"
    return f"/scanner-finding/{index}"

def _title(record: dict[str, Any]) -> str:
    return str(record.get("title") or record.get("plugin_name") or record.get("name") or record.get("vulnerability_id") or record.get("qid") or record.get("plugin_id") or "Scanner finding")

def _vulnerability(record: dict[str, Any]) -> dict[str, Any]:
    value = {"status": _status(record), "severity": record.get("severity", ""), "title": _title(record)}
    for key in ("vulnerability_id", "qid", "plugin_id", "cve", "cvss_v3", "cvss_v2", "description", "solution", "exploit_available", "attack_complexity", "impact"):
        if key in record and record[key] not in (None, ""):
            value[key] = record[key]
    return value

def normalize_scanner_records(records: list[dict[str, Any]], source: str) -> dict[str, Any]:
    """Map neutral scanner records into CTM assets and findings."""
    assets = {}
    findings = []
    source_name = source.strip().lower()

    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            continue
        target = _target(record)
        asset_id = f"SCANNER-{source_name.upper()}-{target.replace(' ', '-')}"
        assets.setdefault(asset_id, {
            "id": asset_id,
            "name": target,
            "asset_type": "scanner_target",
            "criticality": int(record.get("criticality", 3) or 3),
            "data_classification": record.get("data_classification", "internal"),
            "production": bool(record.get("production", True)),
            "owner": record.get("owner", ""),
            "tags": record.get("tags", []),
        })
        findings.append({
            "id": f"{source_name.upper()}-{index:04d}",
            "asset_id": asset_id,
            "method": str(record.get("method", "GET")).upper(),
            "path": _path(record, index),
            "endpoint_type": str(record.get("endpoint_type") or record.get("service") or "unknown").lower(),
            "exposure": {
                "internet_facing": bool(record.get("internet_facing", False)),
                "authentication_required": bool(record.get("authentication_required", True)),
                "trust_zone": record.get("trust_zone", "internal"),
            },
            "vulnerability": _vulnerability(record),
            "controls": dict(record.get("controls") or {}),
            "evidence": {
                "source": source_name,
                "details": _title(record),
                "scanner_record": record,
                "secret_exposed": bool(record.get("secret_exposed", False)),
                "secret_type": record.get("secret_type"),
            },
        })
    return {"assets": assets, "findings": findings}

def scanner_records_to_findings(records: list[dict[str, Any]], source: str) -> list[Finding]:
    data = normalize_scanner_records(records, source)
    return [Finding(**item) for item in data["findings"]]

def scanner_assets(records: list[dict[str, Any]], source: str) -> dict[str, Asset]:
    data = normalize_scanner_records(records, source)
    return {key: Asset(**value) for key, value in data["assets"].items()}
