"""Registry for CTM scanner adapters."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import ScannerAdapter
from .generic_json import GenericJSONAdapter
from .nessus import NessusAdapter
from .nmap import NmapAdapter
from .nuclei import NucleiAdapter
from .qualys import QualysCSVAdapter, QualysXMLAdapter
from .trivy import TrivyAdapter

ADAPTERS: dict[str, type[ScannerAdapter]] = {
    "generic-json": GenericJSONAdapter,
    "nmap": NmapAdapter,
    "nuclei": NucleiAdapter,
    "trivy": TrivyAdapter,
    "qualys-xml": QualysXMLAdapter,
    "qualys-csv": QualysCSVAdapter,
    "nessus": NessusAdapter,
}


def get_adapter(name: str) -> ScannerAdapter:
    """Return an adapter for a supported scanner name."""
    key = name.strip().lower()
    try:
        return ADAPTERS[key]()
    except KeyError as exc:
        supported = ", ".join(sorted(ADAPTERS))
        raise ValueError(f"Unknown scanner '{name}'. Supported: {supported}") from exc


def parse_export(name: str, path: str | Path) -> list[dict[str, Any]]:
    """Parse an export with the named scanner adapter."""
    return get_adapter(name).parse(path)


def list_adapters() -> list[str]:
    """List supported adapter names."""
    return sorted(ADAPTERS)
