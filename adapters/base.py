"""Common adapter contract for CTM scanner exports."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


def ensure_adapter_path(path: str | Path) -> Path:
    """Validate and normalize the input path before parsing a scanner export."""
    resolved = Path(path)
    if not resolved.exists():
        raise FileNotFoundError(f"Scanner export not found: {resolved}")
    if not resolved.is_file():
        raise ValueError(f"Scanner export path is not a file: {resolved}")
    return resolved


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    """Ensure a parsed export section is a dictionary."""
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object, got {type(value).__name__}")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    """Ensure a parsed export section is a list."""
    if not isinstance(value, list):
        raise TypeError(f"{label} must be a list, got {type(value).__name__}")
    return value


class ScannerAdapter(ABC):
    """Common interface for all scanner export adapters."""

    name: str = ""

    @abstractmethod
    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        """Parse an export into CTM-neutral scanner records."""
        raise NotImplementedError
