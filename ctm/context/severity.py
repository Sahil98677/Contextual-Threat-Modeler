"""Normalize scanner severity values without silently downgrading numeric values."""
from __future__ import annotations

from typing import Any

# Nessus severity: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical.
NESSUS_SEVERITY = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}
# Qualys severity: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical.
QUALYS_SEVERITY = {
    "1": "info",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "critical",
}
TEXT_SEVERITY = {
    "critical": "critical",
    "urgent": "critical",
    "very high": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "unknown",
    "": "unknown",
}


def normalize_severity(value: Any, source: str = "", risk_factor: Any = None) -> str:
    """Return canonical severity; source-specific numeric schemes are respected.

    A valid textual/numeric severity wins. Risk factor is used only when the
    severity is missing or unknown, avoiding silent downgrade and conflicts.
    """
    raw = "" if value is None else str(value).strip().lower()
    source_name = str(source or "").strip().lower()

    if raw in TEXT_SEVERITY and TEXT_SEVERITY[raw] != "unknown":
        return TEXT_SEVERITY[raw]

    if source_name == "nessus" and raw in NESSUS_SEVERITY:
        return NESSUS_SEVERITY[raw]
    if source_name.startswith("qualys") and raw in QUALYS_SEVERITY:
        return QUALYS_SEVERITY[raw]

    # For generic sources, don't guess which numeric scale was used.
    fallback = "" if risk_factor is None else str(risk_factor).strip().lower()
    if fallback in TEXT_SEVERITY and TEXT_SEVERITY[fallback] != "unknown":
        return TEXT_SEVERITY[fallback]
    return "info" if raw in {"unknown", "none", "null"} else "info"
