"""Registry for CTM scanner adapters."""
from __future__ import annotations

from pathlib import Path

from .base import ScannerAdapter
from .generic_json import GenericJSONAdapter
from .nmap import NmapAdapter
from .nuclei import NucleiAdapter
from .nessus import NessusAdapter
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
    key = name.strip().lower()
    try:
        return ADAPTERS[key]()
    except KeyError as exc:
        supported = ", ".join(sorted(ADAPTERS))
        raise ValueError(f"Unknown scanner '{name}'. Supported: {supported}") from exc


def parse_export(name: str, path: str | Path) -> list[dict]:
    return get_adapter(name).parse(path)


def list_adapters() -> list[str]:
    return sorted(ADAPTERS)
