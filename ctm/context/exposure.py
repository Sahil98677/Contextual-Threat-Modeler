from .values import as_bool


def exposure_factors(exposure: dict) -> dict[str, float]:
    trust_zone = exposure.get("trust_zone")
    normalized_trust_zone = str(trust_zone).strip().upper() if trust_zone is not None else ""
    factors = {
        "internet_facing": 3.0 if as_bool(exposure.get("internet_facing"), True) else 0.0,
        "unauthenticated": 2.0
        if not as_bool(exposure.get("authentication_required"), False)
        else 0.0,
        "dmz": 0.0 if normalized_trust_zone == "INTERNAL" else 1.0,
    }
    factors["total"] = sum(factors.values())
    return factors
