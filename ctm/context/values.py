"""Shared normalization helpers for untrusted input values."""
from __future__ import annotations

from typing import Any


def as_bool(value: Any, default: bool = False) -> bool:
    """Parse common boolean representations without bool("false") pitfalls."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1", "on"}:
            return True
        if normalized in {"false", "no", "n", "0", "off", ""}:
            return False
    return default
