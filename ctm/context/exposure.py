from .values import as_bool


def exposure_factors(exposure: dict) -> dict[str, float]:
    factors = {
        "internet_facing": 3.0 if as_bool(exposure.get("internet_facing")) else 0.0,
        "unauthenticated": 2.0
        if not as_bool(exposure.get("authentication_required", True), True)
        else 0.0,
        "dmz": 1.0 if str(exposure.get("trust_zone", "")).upper() == "DMZ" else 0.0,
    }
    factors["total"] = sum(factors.values())
    return factors
