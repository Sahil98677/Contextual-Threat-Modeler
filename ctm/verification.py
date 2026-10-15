from datetime import datetime
from typing import Any

VALID_STATUSES = {"validated", "confirmed"}
VALID_DECISIONS = {"verified", "rejected"}


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return False

    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def has_controlled_verification(provenance: Any) -> bool:
    """Return whether provenance contains a complete CTM verification record."""
    if not isinstance(provenance, dict):
        return False

    reviewer_id = provenance.get("reviewer_id")
    evidence_reference = provenance.get("evidence_reference")

    return (
        provenance.get("status_origin") == "ctm_verified"
        and provenance.get("independently_verified") is True
        and provenance.get("decision") == "verified"
        and isinstance(reviewer_id, str)
        and bool(reviewer_id.strip())
        and isinstance(evidence_reference, str)
        and bool(evidence_reference.strip())
        and _valid_timestamp(provenance.get("verified_at"))
    )


def record_verification(
    finding,
    *,
    reviewer_id: str,
    evidence_reference: str,
    verified_at: str,
    decision: str,
    status: str = "validated",
) -> None:
    """Record a review result on a CTM finding.

    The caller must authenticate and authorize the reviewer separately.
    Evidence references should point to controlled records, not contain secrets.
    """
    if not isinstance(reviewer_id, str) or not reviewer_id.strip():
        raise ValueError("reviewer_id must be a non-empty string")

    if not isinstance(evidence_reference, str) or not evidence_reference.strip():
        raise ValueError("evidence_reference must be a non-empty string")

    if not _valid_timestamp(verified_at):
        raise ValueError("verified_at must be a timezone-aware ISO-8601 timestamp")

    if not isinstance(decision, str) or decision not in VALID_DECISIONS:
        raise ValueError("decision must be 'verified' or 'rejected'")

    if decision == "verified" and (
        not isinstance(status, str) or status not in VALID_STATUSES
    ):
        raise ValueError("verified status must be 'validated' or 'confirmed'")

    if decision == "verified":
        finding.vulnerability["status"] = status
        origin = "ctm_verified"
        independently_verified = True
    else:
        origin = "ctm_reviewed"
        independently_verified = False

    finding.evidence["validation_provenance"] = {
        "status_origin": origin,
        "independently_verified": independently_verified,
        "decision": decision,
        "reviewer_id": reviewer_id.strip(),
        "verified_at": verified_at.strip(),
        "evidence_reference": evidence_reference.strip(),
    }
