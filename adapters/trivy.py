"""Trivy JSON scanner adapter."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import ScannerAdapter


def _cvss_score(vuln: dict[str, Any]) -> float | None:
    cvss = vuln.get("CVSS") or {}
    for vendor in ("nvd", "redhat", "ghsa"):
        score = (cvss.get(vendor) or {}).get("V3Score")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                pass
    return None


class TrivyAdapter(ScannerAdapter):
    name = "trivy"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        records = []
        for target in data.get("Results", []) or []:
            target_name = target.get("Target", "unknown")
            for vuln in target.get("Vulnerabilities", []) or []:
                records.append({
                    "source": self.name,
                    "target": target_name,
                    "vulnerability_id": vuln.get("VulnerabilityID", "UNKNOWN"),
                    "package": vuln.get("PkgName", "unknown-pkg"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "cvss_v3": _cvss_score(vuln),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "primary_url": vuln.get("PrimaryURL", ""),
                    "references": vuln.get("References", []) or [],
                })
        return records
