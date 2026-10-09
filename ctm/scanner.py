"""Map scanner adapter records into CTM Finding-compatible data."""
from __future__ import annotations

import re
from typing import Any

from .context.severity import normalize_severity
from .models import Asset, Finding

VALID_STATUSES = {"discovered", "suspected", "validated", "confirmed"}

SEVERITY_STATUS = {
    "critical": "confirmed",
    "high": "validated",
    "medium": "suspected",
    "moderate": "suspected",
    "low": "discovered",
    "info": "discovered",
    "informational": "discovered",
    "unknown": "discovered",
}

SEVERITY_LEVELS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
}


def _as_bool(value: Any, default: bool = False) -> bool:
    """Parse common boolean representations without bool('false') pitfalls."""
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


def _criticality(value: Any) -> int:
    """Normalize scanner-provided asset criticality to CTM's 1–5 range."""
    try:
        parsed = int(float(value))
    except (TypeError, ValueError):
        return 3
    return max(1, min(5, parsed))


def _status(record: dict[str, Any], normalized_severity: str | None = None) -> str:
    """Derive status from explicit status or canonical, source-normalized severity."""
    explicit = str(record.get("status", "")).strip().lower()
    if explicit in VALID_STATUSES:
        return explicit

    severity = normalized_severity
    if severity is None:
        severity = str(record.get("severity", "")).strip().lower()
    return SEVERITY_STATUS.get(severity, "discovered")


def _normalized_severity(value: Any, source: str = "", risk_factor: Any = None) -> str:
    """Normalize severity using the source scanner's documented numeric scale."""
    return normalize_severity(value, source=source, risk_factor=risk_factor)


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
    source_part = source_part or "SCANNER"
    target_part = target_part or "UNKNOWN"
    return f"SCANNER-{source_part}-{target_part}"


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
    risk_factor = record.get("risk_factor")
    severity = _normalized_severity(
        record.get("severity"), source=source, risk_factor=risk_factor
    )
    value = {
        "status": _status(record, normalized_severity=severity),
        "severity": severity,
        "title": _title(record),
    }

    for key in (
        "vulnerability_id",
        "qid",
        "plugin_id",
        "cve",
        "cvss_v3",
        "cvss_v2",
        "description",
        "solution",
        "exploit_available",
        "attack_complexity",
        "impact",
        "risk_factor",
    ):
        if key in record and record[key] not in (None, ""):
            value[key] = record[key]

    if "exploit_available" in value:
        value["exploit_available"] = _as_bool(value["exploit_available"])
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

        assets.setdefault(
            asset_id,
            {
                "id": asset_id,
                "name": target,
                "asset_type": "scanner_target",
                "criticality": _criticality(record.get("criticality", 3)),
                "data_classification": str(
                    record.get("data_classification", "internal")
                ).lower(),
                "production": _as_bool(record.get("production", True), True),
                "owner": str(record.get("owner", "")),
                "tags": list(record.get("tags", []))
                if isinstance(record.get("tags", []), (list, tuple))
                else [],
            },
        )

        findings.append(
            {
                "id": f"{source_name.upper()}-{index:04d}",
                "asset_id": asset_id,
                "method": str(record.get("method", "GET")).upper(),
                "path": _path(record, index),
                "endpoint_type": str(
                    record.get("endpoint_type")
                    or record.get("service")
                    or "unknown"
                ).lower(),
                "exposure": {
                    "internet_facing": _as_bool(
                        record.get("internet_facing", False)
                    ),
                    "authentication_required": _as_bool(
                        record.get("authentication_required", True), True
                    ),
                    "trust_zone": record.get("trust_zone", "internal"),
                },
                "vulnerability": _vulnerability(record, source_name),
                "controls": dict(record.get("controls") or {})
                if isinstance(record.get("controls") or {}, dict)
                else {},
                "evidence": {
                    "source": source_name,
                    "details": _title(record),
                    "scanner_record": record,
                    "secret_exposed": _as_bool(
                        record.get("secret_exposed", False)
                    ),
                    "secret_type": record.get("secret_type"),
                },
            }
        )

    return {"assets": assets, "findings": findings}


def scanner_records_to_findings(
    records: list[dict[str, Any]],
    source: str,
) -> list[Finding]:
    data = normalize_scanner_records(records, source)
    return [Finding(**item) for item in data["findings"]]


def scanner_assets(
    records: list[dict[str, Any]],
    source: str,
) -> dict[str, Asset]:
    data = normalize_scanner_records(records, source)
    return {key: Asset(**value) for key, value in data["assets"].items()}
