"""Qualys XML and CSV scanner adapters."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET

from .base import ScannerAdapter


def _child_text(element: ET.Element, *names: str) -> str:
    for name in names:
        child = element.find(f".//{name}")
        if child is not None and child.text:
            return child.text.strip()
    return ""


def _attr_or_child(element: ET.Element, *names: str) -> str:
    for name in names:
        value = element.get(name)
        if value not in (None, ""):
            return value
    return _child_text(element, *names)


def _float(value: str | None) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


class QualysXMLAdapter(ScannerAdapter):
    name = "qualys-xml"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        root = ET.parse(Path(path)).getroot()
        records = []
        elements = root.findall(".//VULN") or root.findall(".//Vulnerability")

        for vuln in elements:
            records.append({
                "source": "qualys",
                "host": _attr_or_child(vuln, "host", "IP", "ip", "asset", "asset_id"),
                "qid": _attr_or_child(vuln, "number", "qid", "QID", "id"),
                "title": _attr_or_child(vuln, "title", "TITLE", "name"),
                "severity": _attr_or_child(vuln, "severity", "SEVERITY"),
                "cvss_v3": _float(_attr_or_child(vuln, "cvss3_base", "CVSS3_BASE", "cvss_v3")),
                "cve": _attr_or_child(vuln, "cve", "CVE_ID", "cve_id"),
                "category": _attr_or_child(vuln, "category", "CATEGORY"),
                "diagnosis": _child_text(vuln, "DIAGNOSIS", "diagnosis"),
                "solution": _child_text(vuln, "SOLUTION", "solution"),
            })
        return records


class QualysCSVAdapter(ScannerAdapter):
    name = "qualys-csv"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        records = []
        with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                lowered = {str(k).strip().lower(): v for k, v in row.items()}
                records.append({
                    "source": "qualys",
                    "host": lowered.get("host") or lowered.get("ip") or lowered.get("asset") or "",
                    "qid": lowered.get("qid") or lowered.get("qid id") or "",
                    "title": lowered.get("title") or lowered.get("vulnerability") or "",
                    "severity": lowered.get("severity") or "",
                    "cvss_v3": _float(
                        lowered.get("cvss v3")
                        or lowered.get("cvss v3 base")
                        or lowered.get("cvss3 base score")
                    ),
                    "cve": lowered.get("cve") or lowered.get("cve id") or "",
                    "category": lowered.get("category") or "",
                    "diagnosis": lowered.get("diagnosis") or "",
                    "solution": lowered.get("solution") or "",
                })
        return records
