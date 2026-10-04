import json
from pathlib import Path


def parse_jsonl(path: str | Path) -> list[dict]:
    """Read Nuclei JSONL output as neutral records without executing Nuclei."""
    records = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
