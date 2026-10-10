"""Nuclei JSONL scanner adapter."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import ScannerAdapter


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        records = []
        with Path(path).open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise TypeError("Each non-empty Nuclei JSONL line must contain an object")
                    records.append(record)
        return records
