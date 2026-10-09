"""Validation helpers for scanner-to-CTM pipeline results."""
from __future__ import annotations

from collections import Counter
from typing import Any

from .decision.thresholds import CRITICAL_THRESHOLD, HIGH_THRESHOLD, MEDIUM_THRESHOLD


def summarize_findings(findings: list[Any]) -> dict[str, Any]:
    scores = [float(item.score) for item in findings]
    return {
        "total_findings": len(findings),
        "risk_levels": dict(Counter(_risk_level(score) for score in scores)),
        "decisions": dict(Counter(item.decision for item in findings)),
        "average_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
        "highest_score": max(scores) if scores else 0.0,
        "mitre_techniques": sorted({technique for item in findings for technique in item.attack_techniques}),
        "stride_threats": sorted({threat for item in findings for threat in item.threats}),
    }


def _risk_level(score: float) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"
