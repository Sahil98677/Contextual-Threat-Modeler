"""Nessus .nessus XML scanner adapter."""
from __future__ import annotations

from defusedxml import ElementTree as ET
from pathlib import Path
from typing import Any

from .base import ScannerAdapter


def _text(element: ET.Element | None, name: str) -> str | None:
    child = element.find(name) if element is not None else None
    return child.text.strip() if child is not None and child.text else None


def _float(value: str | None) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


class NessusAdapter(ScannerAdapter):
    name = "nessus"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        root = ET.parse(Path(path)).getroot()
        records = []
        for report_host in root.findall(".//ReportHost"):
            host = report_host.get("name", "unknown")
            for item in report_host.findall("ReportItem"):
                severity = item.get("severity", "0")
                records.append({
                    "source": self.name,
                    "host": host,
                    "plugin_id": item.get("pluginID"),
                    "plugin_name": item.get("pluginName", ""),
                    "port": int(item.get("port", 0) or 0),
                    "protocol": item.get("protocol", ""),
                    "service": item.get("svc_name", ""),
                    "severity": int(severity) if severity.isdigit() else severity,
                    "risk_factor": item.get("risk_factor", ""),
                    "cve": item.get("cve", ""),
                    "cvss_v2": _float(item.get("cvss_base_score")),
                    "cvss_v3": _float(item.get("cvss3_base_score")),
                    "description": _text(item, "description") or "",
                    "solution": _text(item, "solution") or "",
                    "plugin_output": _text(item, "plugin_output") or "",
                })
        return records
