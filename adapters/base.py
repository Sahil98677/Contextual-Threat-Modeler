"""Common adapter contract for CTM scanner exports."""
from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

class ScannerAdapter(ABC):
    """Base interface implemented by CTM scanner adapters."""
    name: str = ""

    @abstractmethod
    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        """Parse a scanner export into neutral records."""
        raise NotImplementedError
