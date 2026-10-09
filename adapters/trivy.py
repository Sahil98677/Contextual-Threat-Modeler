"""Trivy JSON scanner adapter."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


from .base import ScannerAdapter


def _cvss_score(vuln: dict[str, Any]) -> float | None:
    """Extract a CVSS v3 score from common Trivy vendor records."""
    cvss = vuln.get("CVSS") or {}
    if not isinstance(cvss, dict):
        return None

    for vendor in ("nvd", "redhat", "ghsa"):
        vendor_data = cvss.get(vendor) or {}
        if not isinstance(vendor_data, dict):
            continue
        score = vendor_data.get("V3Score")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                continue
    return None


class TrivyAdapter(ScannerAdapter):
    """Parse Trivy JSON reports."""

    name = "trivy"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        if not isinstance(data, dict):
            raise TypeError("Trivy export must contain a JSON object.")

        records: list[dict[str, Any]] = []
        results = data.get("Results", []) or []
        if not isinstance(results, list):
            return records

        for target in results:
            if not isinstance(target, dict):
                continue
            target_name = target.get("Target", "unknown")
            vulnerabilities = target.get("Vulnerabilities", []) or []
            if not isinstance(vulnerabilities, list):
                continue

            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                records.append(
                    {
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
                    }
                )
        return records
