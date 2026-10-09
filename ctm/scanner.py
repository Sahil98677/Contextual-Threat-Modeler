"""Map scanner adapter records into CTM Finding-compatible data."""
from __future__ import annotations

import re
from typing import Any

from .context.severity import normalize_severity
from .context.values import as_bool
from .models import Asset, Finding

VALID_STATUSES = {"discovered", "suspected", "validated", "confirmed"}

SEVERITY_STATUS = {
    "critical": "confirmed",
    "high": "validated",
    "medium": "suspected",
    "low": "discovered",
    "info": "discovered",
    "unknown": "discovered",
}

SEVERITY_LEVELS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


def _criticality(value: Any) -> int:
    """Normalize scanner-provided asset criticality to CTM's 1–5 range."""
    try:
        parsed = int(float(value))
    except (TypeError, ValueError):
        return 3
    return max(1, min(5, parsed))


def _status(record: dict[str, Any], severity: str) -> str:
    explicit = str(record.get("status", "")).strip().lower()
    if explicit in VALID_STATUSES:
        return explicit
    return SEVERITY_STATUS.get(severity, "discovered")


def _target(record: dict[str, Any]) -> str:
    return str(
        record.get("target")
        or record.get("host")
        or record.get("ip")
        or record.get("asset")
        or "unknown"
    ).strip()


def _safe_asset_id(source: str, target: str) -> str:
    """Create deterministic, filesystem/JSON friendly asset identifiers."""
    source_part = re.sub(r"[^A-Za-z0-9_-]+", "-", source.strip().upper()).strip("-")
    target_part = re.sub(r"[^A-Za-z0-9_.:-]+", "-", target.strip()).strip("-")
    return f"SCANNER-{source_part or 'SCANNER'}-{target_part or 'UNKNOWN'}"


def _path(record: dict[str, Any], index: int) -> str:
    path = record.get("path") or record.get("url")
    if path:
        return str(path)
    if record.get("port") not in (None, ""):
        return f"{record.get('service') or 'tcp'}/{record['port']}"
    return f"/scanner-finding/{index}"


def _title(record: dict[str, Any]) -> str:
    return str(
        record.get("title")
        or record.get("plugin_name")
        or record.get("name")
        or record.get("vulnerability_id")
        or record.get("qid")
        or record.get("plugin_id")
        or "Scanner finding"
    )


def _vulnerability(record: dict[str, Any], source: str) -> dict[str, Any]:
    severity = normalize_severity(
        record.get("severity"),
        source=source,
        risk_factor=record.get("risk_factor"),
    )
    value: dict[str, Any] = {
        "status": _status(record, severity),
        "severity": severity,
        "title": _title(record),
    }
    for key in (
        "vulnerability_id", "qid", "plugin_id", "cve", "cvss_v3", "cvss_v2",
        "description", "solution", "exploit_available", "attack_complexity",
        "impact", "risk_factor", "package", "installed_version", "fixed_version",
        "primary_url", "references", "plugin_output", "category", "diagnosis",
    ):
        if key in record and record[key] not in (None, ""):
            value[key] = record[key]
    if "exploit_available" in value:
        value["exploit_available"] = as_bool(value["exploit_available"])
    return value


def normalize_scanner_records(
    records: list[dict[str, Any]],
    source: str,
) -> dict[str, Any]:
    """Map neutral scanner records into CTM assets and findings."""
    assets: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    source_name = source.strip().lower() or "unknown"

    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            continue
        target = _target(record)
        asset_id = _safe_asset_id(source_name, target)
        assets.setdefault(asset_id, {
            "id": asset_id,
            "name": target,
            "asset_type": record.get("asset_type", "scanner_target"),
            "criticality": _criticality(record.get("criticality", 3)),
            "data_classification": str(record.get("data_classification", "internal")).lower(),
            "production": as_bool(record.get("production", True), True),
            "owner": str(record.get("owner", "")),
            "tags": list(record.get("tags", []))
                if isinstance(record.get("tags", []), (list, tuple)) else [],
        })
        findings.append({
            "id": f"{source_name.upper()}-{index:04d}",
            "asset_id": asset_id,
            "method": str(record.get("method", "GET")).upper(),
            "path": _path(record, index),
            "endpoint_type": str(record.get("endpoint_type") or record.get("service") or "unknown").strip().lower(),
            "exposure": {
                "internet_facing": as_bool(record.get("internet_facing", False)),
                "authentication_required": as_bool(record.get("authentication_required", True), True),
                "trust_zone": record.get("trust_zone", "internal"),
            },
            "vulnerability": _vulnerability(record, source_name),
            "controls": dict(record.get("controls") or {}) if isinstance(record.get("controls") or {}, dict) else {},
            "evidence": {
                "source": source_name,
                "details": _title(record),
                "scanner_record": record,
                "secret_exposed": as_bool(record.get("secret_exposed", False)),
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
