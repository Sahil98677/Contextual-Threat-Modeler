from ..models import Asset


def normalize_criticality(value: int | float) -> int:
    return max(1, min(5, int(value)))


def build_asset(raw: dict) -> Asset:
    return Asset(
        id=raw["id"],
        name=raw["name"],
        asset_type=raw.get("asset_type", "web_application"),
        criticality=normalize_criticality(raw.get("criticality", 3)),
        data_classification=raw.get("data_classification", "internal").lower(),
        production=bool(raw.get("production", True)),
        owner=raw.get("owner", ""),
        tags=list(raw.get("tags", [])),
    )
