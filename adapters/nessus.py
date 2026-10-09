"""Nessus .nessus XML scanner adapter."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as ET

from .base import ScannerAdapter


def _text(element: Element | None, name: str) -> str | None:
    """Return stripped child text, if present."""
    if element is None:
        return None
    child = element.find(name)
    if child is None or child.text is None:
        return None
    return child.text.strip()


def _float(value: str | None) -> float | None:
    """Convert a string to float without raising on empty or invalid values."""
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


class NessusAdapter(ScannerAdapter):
    """Parse Nessus XML exports."""

    name = "nessus"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        tree = ET.parse(Path(path))
        root = tree.getroot()
        if root is None:
            raise ValueError("Nessus XML export has no root element.")

        records: list[dict[str, Any]] = []
        for report_host in root.findall(".//ReportHost"):
            host = report_host.get("name", "unknown")
            for item in report_host.findall("ReportItem"):
                severity = item.get("severity", "0")
                port_text = item.get("port", "0") or "0"
                try:
                    port = int(port_text)
                except ValueError:
                    port = 0

                records.append(
                    {
                        "source": self.name,
                        "host": host,
                        "plugin_id": item.get("pluginID"),
                        "plugin_name": item.get("pluginName", ""),
                        "port": port,
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
                    }
                )
        return records
