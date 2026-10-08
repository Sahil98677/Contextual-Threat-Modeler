"""Registry for CTM scanner adapters."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Callable

from .generic_json import load as load_generic_json
from .nmap import parse_xml as parse_nmap_xml
from .nuclei import parse_jsonl as parse_nuclei_jsonl
from .nessus import parse_xml as parse_nessus_xml
from .qualys import parse_csv as parse_qualys_csv
from .qualys import parse_xml as parse_qualys_xml
from .trivy import parse_json as parse_trivy_json

Parser = Callable[[str | Path], Any]

PARSERS: dict[str, Parser] = {
    "generic-json": load_generic_json,
    "nmap": parse_nmap_xml,
    "nuclei": parse_nuclei_jsonl,
    "trivy": parse_trivy_json,
    "qualys-xml": parse_qualys_xml,
    "qualys-csv": parse_qualys_csv,
    "nessus": parse_nessus_xml,
}

def get_parser(name: str) -> Parser:
    key = name.strip().lower()
    try:
        return PARSERS[key]
    except KeyError as exc:
        supported = ", ".join(sorted(PARSERS))
        raise ValueError(f"Unknown scanner '{name}'. Supported: {supported}") from exc

def parse_export(name: str, path: str | Path) -> list[dict[str, Any]]:
    """Parse an export and always return a list of dictionary records."""
    result = get_parser(name)(path)
    if result is None:
        return []
    if isinstance(result, list):
        return [item for item in result if isinstance(item, dict)]
    if isinstance(result, dict):
        return [result]
    raise TypeError(f"Adapter '{name}' returned unsupported type: {type(result).__name__}")

def list_adapters() -> list[str]:
    return sorted(PARSERS)
