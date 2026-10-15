"""Shared normalization helpers for untrusted input values."""
from __future__ import annotations

import math
from typing import Any


def as_bool(value: Any, default: bool = False) -> bool:
    """Parse common boolean representations without bool("false") pitfalls."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return default
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1", "on"}:
            return True
        if normalized in {"false", "no", "n", "0", "off", ""}:
            return False
    return default


def as_optional_bool(value: Any) -> bool | None:
    """Parse a boolean value while preserving missing and unrecognized input."""
    if value is None:
        return None
    if isinstance(value, (bool, int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return as_bool(value)
    if isinstance(value, str) and value.strip().lower() in {
        "true",
        "yes",
        "y",
        "1",
        "on",
        "false",
        "no",
        "n",
        "0",
        "off",
        "",
    }:
        return as_bool(value)
    return None
