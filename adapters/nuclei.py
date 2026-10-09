"""Nuclei JSONL scanner adapter."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import ScannerAdapter


class NucleiAdapter(ScannerAdapter):
    """Parse Nuclei JSON Lines exports."""

    name = "nuclei"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        with Path(path).open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid Nuclei JSON on line {line_number}: {exc.msg}"
                    ) from exc
                if isinstance(record, dict):
                    records.append(record)
        return records
