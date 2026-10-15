import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from ctm.models import Finding

VALID_STATUSES = {"validated", "confirmed"}
VALID_DECISIONS = {"verified", "rejected"}
AUDIT_TRAIL_KEY = "verification_audit_trail"
VERIFICATION_PERMISSIONS = {
    "verified": "finding:verify",
    "rejected": "finding:reject",
}


class VerificationAuthorizer(Protocol):
    """Trusted adapter to the application's authenticated identity and ACL."""

    def authorize(self, finding_id: str, permission: str) -> str:
        """Authorize an action and return its authenticated reviewer subject."""
        ...


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


def _event_hash(event: dict[str, Any]) -> str:
    """Calculate a stable hash for an audit event, excluding its own hash."""
    payload = {key: value for key, value in event.items() if key != "event_hash"}
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_audit_trail(events: Any) -> bool:
    """Check audit event hashes and links from the beginning of the trail."""
    if not isinstance(events, list):
        return False

    previous_hash = ""

    for event in events:
        if not isinstance(event, dict):
            return False

        if event.get("previous_event_hash") != previous_hash:
            return False

        recorded_hash = event.get("event_hash")
        if not isinstance(recorded_hash, str) or not recorded_hash:
            return False

        try:
            expected_hash = _event_hash(event)
        except (TypeError, ValueError):
            return False
        if recorded_hash != expected_hash:
            return False

        previous_hash = recorded_hash

    return True


def record_verification(
    finding: Finding,
    *,
    authorizer: VerificationAuthorizer,
    evidence_reference: str,
    verified_at: str,
    decision: str,
    status: str = "validated",
) -> None:
    """Record a review result on a CTM finding.

    The authorizer must be supplied by trusted application code. It must resolve
    the authenticated identity and enforce the requested decision permission.
    This operation does not itself authenticate the reviewer.
    Evidence references should point to controlled records, not contain secrets.

    The trail is tamper-evident, not immutable storage. Production deployments
    should also persist events to access-controlled, append-only storage.
    """
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

    reviewer_id = authorizer.authorize(
        finding.id,
        VERIFICATION_PERMISSIONS[decision],
    )
    if not isinstance(reviewer_id, str) or not reviewer_id.strip():
        raise PermissionError("authorizer did not provide an authenticated reviewer")

    audit_trail = finding.evidence.get(AUDIT_TRAIL_KEY, [])
    if not isinstance(audit_trail, list) or not verify_audit_trail(audit_trail):
        raise ValueError("existing verification audit trail is invalid")

    previous_status = finding.vulnerability.get("status", "discovered")
    new_status = status if decision == "verified" else previous_status
    previous_hash = audit_trail[-1]["event_hash"] if audit_trail else ""

    event = {
        "reviewer_id": reviewer_id.strip(),
        "evidence_reference": evidence_reference.strip(),
        "verified_at": verified_at.strip(),
        "decision": decision,
        "previous_status": previous_status,
        "new_status": new_status,
        "previous_event_hash": previous_hash,
    }
    event["event_hash"] = _event_hash(event)

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

    audit_trail.append(event)
    finding.evidence[AUDIT_TRAIL_KEY] = audit_trail
