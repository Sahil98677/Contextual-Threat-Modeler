"""Generic JSON scanner adapter."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import ScannerAdapter, ensure_adapter_path, require_list, require_mapping


class GenericJSONAdapter(ScannerAdapter):
    name = "generic-json"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        file_path = ensure_adapter_path(path)
        with file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        if isinstance(data, list):
            records = require_list(data, "Generic JSON export")
            for index, item in enumerate(records):
                require_mapping(item, f"Generic JSON export record {index}")
            return records
        if isinstance(data, dict):
            return [require_mapping(data, "Generic JSON export")]
        raise TypeError("Generic JSON export must contain an object or array")
