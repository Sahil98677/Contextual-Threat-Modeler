from pathlib import Path
import json


def load(path: str | Path) -> object:
    """Load a generic JSON scanner export without changing its schema."""
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)
