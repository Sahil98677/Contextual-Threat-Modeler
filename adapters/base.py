"""Common adapter contract for CTM scanner exports."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class ScannerAdapter(ABC):
    """Common interface for all scanner export adapters."""

    name: str = ""

    @abstractmethod
    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        """Parse an export into CTM-neutral scanner records."""
        raise NotImplementedError
