from ..context.controls import control_modifier
from .confidence import calculate_confidence
from .impact import calculate_impact
from .likelihood import calculate_likelihood


def calculate_risk(finding, asset) -> None:
    finding.likelihood = round(calculate_likelihood(finding), 2)
    finding.impact = round(calculate_impact(finding, asset), 2)
    finding.confidence = calculate_confidence(finding)

    modifier = control_modifier(finding.controls)
    raw_score = finding.likelihood * finding.impact
    finding.score = round(min(100.0, raw_score * modifier), 1)

    if finding.evidence.get("secret_exposed"):
        finding.score = max(finding.score, 85.0)

    finding.rationale = []
    if finding.exposure.get("internet_facing"):
        finding.rationale.append("Internet-facing attack surface increases exposure.")
    if not finding.exposure.get("authentication_required", True):
        finding.rationale.append("No authentication is required before reaching the endpoint.")
    if asset.criticality >= 4:
        finding.rationale.append("The target asset has high business criticality.")
    if asset.data_classification in ("confidential", "restricted"):
        finding.rationale.append("The asset handles sensitive data.")
    if finding.evidence.get("secret_exposed"):
        finding.rationale.append("Potential secret exposure materially increases impact.")
    if finding.vulnerability.get("status") in ("validated", "confirmed"):
        finding.rationale.append("The vulnerability has validation evidence.")
    if modifier < 1.0:
        finding.rationale.append("Existing security controls reduce, but do not eliminate, risk.")
