from ctm.models import Finding

from .mitre import map_mitre, mitre_mapping_evidence
from .stride import map_stride, stride_mapping_evidence


def apply_threat_mappings(finding: Finding) -> None:
    """Apply current STRIDE/ATT&CK candidate mappings and retain their basis."""
    internet_facing = finding.exposure.get("internet_facing")
    vulnerability = finding.vulnerability
    finding.threats = map_stride(finding.endpoint_type)
    finding.attack_techniques = map_mitre(
        finding.endpoint_type,
        internet_facing is True,
        vulnerability,
    )
    finding.evidence["threat_mapping_evidence"] = {
        "stride": stride_mapping_evidence(finding.endpoint_type),
        "mitre_attack": mitre_mapping_evidence(
            finding.endpoint_type,
            internet_facing,
            vulnerability,
        ),
    }
