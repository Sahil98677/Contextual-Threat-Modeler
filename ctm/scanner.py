"""Map scanner adapter records into CTM Finding-compatible data."""
from __future__ import annotations

import hashlib
import math
import re
from typing import Any

from .context.severity import normalize_severity
from .context.values import as_optional_bool
from .models import Asset, Finding

VALID_STATUSES = {"discovered", "suspected", "validated", "confirmed"}

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
        if isinstance(value, float) and not math.isfinite(value):
            return default
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
    except (OverflowError, TypeError, ValueError):
        return 3
    return max(1, min(5, parsed))


def _data_classification(value: Any) -> str:
    """Normalize asset data classification without trusting scanner types."""
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().lower()
    allowed = {"public", "internal", "confidential", "restricted"}
    return normalized if normalized in allowed else "unknown"


def _tags(value: Any) -> list[str]:
    """Keep only non-empty string tags from untrusted scanner input."""
    if not isinstance(value, (list, tuple)):
        return []
    return [
        tag.strip()
        for tag in value
        if isinstance(tag, str) and tag.strip()
    ]


def _text(value: Any, default: str) -> str:
    """Accept non-empty strings from untrusted scanner input only."""
    if not isinstance(value, str):
        return default
    normalized = value.strip()
    return normalized if normalized else default


def _service(value: Any, default: str = "tcp") -> str:
    """Accept only simple service identifiers from scanner input."""
    if not isinstance(value, str):
        return default
    normalized = value.strip().lower()
    if re.fullmatch(r"[a-z0-9][a-z0-9._+-]{0,63}", normalized):
        return normalized
    return default


def _port(value: Any) -> int | None:
    """Accept integer or digit-string TCP/UDP ports in the valid range."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value.strip()):
        port = int(value.strip())
    else:
        return None
    return port if 1 <= port <= 65535 else None


def _status(record: dict[str, Any]) -> str:
    """Preserve explicit validation status; severity alone is not validation."""
    raw_status = record.get("status")
    explicit = raw_status.strip().lower() if isinstance(raw_status, str) else ""
    if explicit in VALID_STATUSES:
        return explicit
    return "discovered"


def _status_origin(record: dict[str, Any]) -> str:
    """Identify whether validation status came from the scanner or CTM."""
    raw_status = record.get("status")
    explicit = raw_status.strip().lower() if isinstance(raw_status, str) else ""
    return "scanner_reported" if explicit in VALID_STATUSES else "ctm_defaulted"


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
    path = _text(record.get("path"), "")
    if not path:
        path = _text(record.get("url"), "")
    if path:
        return path

    port = _port(record.get("port"))
    if port is not None:
        return f"{_service(record.get('service'))}/{port}"

    return f"/scanner-finding/{index}"


def _title(record: dict[str, Any]) -> str:
    """Select a usable title from untrusted scanner input."""
    for key in (
        "title",
        "plugin_name",
        "name",
        "vulnerability_id",
        "qid",
        "plugin_id",
    ):
        value = _text(record.get(key), "")
        if value:
            return value
    return "Scanner finding"


def _vulnerability(record: dict[str, Any], source: str) -> dict[str, Any]:
    risk_factor = record.get("risk_factor")
    severity = _normalized_severity(
        record.get("severity"), source=source, risk_factor=risk_factor
    )
    result: dict[str, Any] = {
        "status": _status(record),
        "severity": severity,
        "title": _title(record),
    }

    text_fields = (
        "vulnerability_id",
        "qid",
        "plugin_id",
        "cve",
        "description",
        "solution",
        "risk_factor",
        "attack_complexity",
        "impact",
    )
    for key in text_fields:
        value = _text(record.get(key), "")
        if value:
            if key in {"attack_complexity", "impact"}:
                value = value.lower()
            result[key] = value

    for key in ("cvss_v3", "cvss_v2"):
        if key in record and record[key] not in (None, ""):
            result[key] = record[key]

    if "exploit_available" in record and record["exploit_available"] not in (
        None,
        "",
    ):
        result["exploit_available"] = _as_bool(record["exploit_available"])
    return result


def normalize_scanner_records(
    records: list[dict[str, Any]],
    source: str,
) -> dict[str, Any]:
    """Map neutral scanner records into CTM assets and findings."""
    assets: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    source_name = source.strip().lower() or "unknown"

    targets_by_asset_id: dict[str, set[str]] = {}
    for record in records:
        if isinstance(record, dict):
            target = _target(record)
            base_id = _safe_asset_id(source_name, target)
            targets_by_asset_id.setdefault(base_id, set()).add(target)

    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            continue

        target = _target(record)
        asset_id = _safe_asset_id(source_name, target)
        if len(targets_by_asset_id[asset_id]) > 1:
            suffix = hashlib.sha256(target.encode("utf-8")).hexdigest()[:8]
            asset_id = f"{asset_id}-{suffix}"

        assets.setdefault(
            asset_id,
            {
                "id": asset_id,
                "name": target,
                "asset_type": "scanner_target",
                "criticality": _criticality(record.get("criticality", 3)),
                "data_classification": _data_classification(
                    record.get("data_classification", "internal")
                ),
                "production": _as_bool(record.get("production", True), True),
                "owner": _text(record.get("owner"), ""),
                "tags": _tags(record.get("tags", [])),
            },
        )

        findings.append(
            {
                "id": f"{source_name.upper()}-{index:04d}",
                "asset_id": asset_id,
                "method": _text(record.get("method"), "GET").upper(),
                "path": _path(record, index),
                "endpoint_type": _text(
                    record.get("endpoint_type"), ""
                ).lower() or _service(record.get("service"), "unknown"),
                "exposure": {
                    "internet_facing": as_optional_bool(record.get("internet_facing")),
                    "authentication_required": as_optional_bool(
                        record.get("authentication_required")
                    ),
                    "trust_zone": (
                        record.get("trust_zone")
                        if isinstance(record.get("trust_zone"), str)
                        and record["trust_zone"].strip()
                        else None
                    ),
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
                    "secret_type": _text(record.get("secret_type"), "") or None,
                    "validation_provenance": {
                        "status_origin": _status_origin(record),
                        "independently_verified": False,
                    },
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
