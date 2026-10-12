"""Nuclei JSONL scanner adapter."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import ScannerAdapter, ensure_adapter_path, require_mapping


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        file_path = ensure_adapter_path(path)
        records = []
        with file_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                payload = line.strip()
                if not payload:
                    continue
                try:
                    record = json.loads(payload)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON at Nuclei line {line_number}: {exc.msg}") from exc
                records.append(require_mapping(record, f"Nuclei record on line {line_number}"))
        return records
