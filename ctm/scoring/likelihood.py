from ..context.exposure import exposure_factors

STATUS_BONUS = {
    "discovered": 0.0,
    "suspected": 0.75,
    "validated": 1.5,
    "confirmed": 2.0,
}


def calculate_likelihood(finding) -> float:
    factors = exposure_factors(finding.exposure)
    value = 2.0 + factors["total"]
    vulnerability = finding.vulnerability
    value += 2.0 if vulnerability.get("exploit_available") else 0.0
    value += 1.0 if vulnerability.get("attack_complexity") == "low" else 0.0
    value += STATUS_BONUS.get(vulnerability.get("status", "discovered"), 0.0)
    return max(0.0, min(10.0, value))
