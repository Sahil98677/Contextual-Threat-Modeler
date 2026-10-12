"""Trivy JSON scanner adapter."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import ScannerAdapter, ensure_adapter_path, require_list, require_mapping


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
        file_path = ensure_adapter_path(path)
        with file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        payload = require_mapping(data, "Trivy JSON export")
        targets = payload.get("Results", [])
        if targets is None:
            return []
        targets = require_list(targets, "Trivy Results")

        records = []
        for index, target in enumerate(targets):
            target_record = require_mapping(target, f"Trivy result {index}")
            target_name = target_record.get("Target", "unknown")
            vulns = target_record.get("Vulnerabilities", []) or []
            if vulns is None:
                continue
            vulns = require_list(vulns, f"Trivy vulnerabilities for target {target_name}")
            for vuln in vulns:
                vuln_record = require_mapping(vuln, f"Trivy vulnerability for target {target_name}")
                records.append({
                    "source": self.name,
                    "target": target_name,
                    "vulnerability_id": vuln_record.get("VulnerabilityID", "UNKNOWN"),
                    "package": vuln_record.get("PkgName", "unknown-pkg"),
                    "installed_version": vuln_record.get("InstalledVersion"),
                    "fixed_version": vuln_record.get("FixedVersion"),
                    "severity": vuln_record.get("Severity", "UNKNOWN"),
                    "cvss_v3": _cvss_score(vuln_record),
                    "title": vuln_record.get("Title", ""),
                    "description": vuln_record.get("Description", ""),
                    "primary_url": vuln_record.get("PrimaryURL", ""),
                    "references": vuln_record.get("References", []) or [],
                })
        return records
