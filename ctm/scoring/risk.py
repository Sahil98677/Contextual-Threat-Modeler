from ..context.controls import control_modifier
from ..decision.thresholds import CRITICAL_THRESHOLD
from .confidence import calculate_confidence
from .impact import calculate_impact
from .likelihood import calculate_likelihood


def calculate_risk(finding, asset) -> None:
    finding.likelihood = round(calculate_likelihood(finding), 2)
    finding.impact = round(calculate_impact(finding, asset), 2)
    finding.confidence = calculate_confidence(finding)

    modifier = control_modifier(
        finding.controls, finding.endpoint_type, finding.vulnerability
    )
    raw_score = finding.likelihood * finding.impact
    finding.score = round(min(100.0, raw_score * modifier), 1)

    if finding.evidence.get("secret_exposed"):
        finding.score = max(finding.score, CRITICAL_THRESHOLD)

    finding.rationale = []
    if finding.exposure.get("internet_facing") is None:
        finding.rationale.append(
            "Internet-facing exposure is unknown and scored conservatively."
        )
    elif finding.exposure.get("internet_facing"):
        finding.rationale.append("Internet-facing attack surface increases exposure.")
    if finding.exposure.get("authentication_required") is None:
        finding.rationale.append(
            "Authentication requirements are unknown and scored conservatively."
        )
    elif not finding.exposure.get("authentication_required"):
        finding.rationale.append("No authentication is required before reaching the endpoint.")
    trust_zone = finding.exposure.get("trust_zone")
    if (
        not isinstance(trust_zone, str)
        or trust_zone.strip().upper() not in {"INTERNAL", "DMZ", "EXTERNAL"}
    ):
        finding.rationale.append("Trust zone is unknown and scored conservatively.")
    if asset.criticality >= 4:
        finding.rationale.append("The target asset has high business criticality.")
    if asset.data_classification in ("confidential", "restricted"):
        finding.rationale.append("The asset handles sensitive data.")
    if (
        not isinstance(asset.data_classification, str)
        or asset.data_classification.strip().lower() == "unknown"
    ):
        finding.rationale.append(
            "Data classification is unknown and scored conservatively."
        )
    if finding.evidence.get("secret_exposed"):
        finding.rationale.append("Potential secret exposure materially increases impact.")
    if finding.vulnerability.get("exploit_available"):
        finding.rationale.append("An exploit is reported as available, increasing likelihood.")
    if finding.vulnerability.get("attack_complexity") == "low":
        finding.rationale.append("The reported attack complexity is low, increasing likelihood.")
    if finding.vulnerability.get("status") in ("validated", "confirmed"):
        finding.rationale.append("The vulnerability has validation evidence.")
    elif finding.vulnerability.get("status") == "suspected":
        finding.rationale.append("The vulnerability is suspected but has not been validated.")
    if modifier < 1.0:
        finding.rationale.append("Existing security controls reduce, but do not eliminate, risk.")
