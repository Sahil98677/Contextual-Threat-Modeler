"""Generic JSON scanner adapter."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import ScannerAdapter


class GenericJSONAdapter(ScannerAdapter):
    name = "generic-json"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        if isinstance(data, list):
            if not all(isinstance(item, dict) for item in data):
                raise TypeError("Every record in a generic JSON array must be an object")
            return data
        if isinstance(data, dict):
            return [data]
        raise TypeError("Generic JSON export must contain an object or array")
