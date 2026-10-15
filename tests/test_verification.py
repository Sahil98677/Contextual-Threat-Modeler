import inspect

import pytest

from ctm.ingestion import normalize
from ctm.models import Asset, Finding
from ctm.scoring.confidence import calculate_confidence
from ctm.scoring.risk import calculate_risk
from ctm.verification import record_verification, verify_audit_trail


class _TestAuthorizer:
    def __init__(
        self,
        reviewer_id: str = "reviewer-001",
        permissions: set[str] | None = None,
    ) -> None:
        self.reviewer_id = reviewer_id
        self.permissions = permissions if permissions is not None else {
            "finding:verify",
            "finding:reject",
        }
        self.requests: list[tuple[str, str]] = []

    def authorize(self, finding_id: str, permission: str) -> str:
        self.requests.append((finding_id, permission))
        if permission not in self.permissions:
            raise PermissionError("reviewer is not authorized")
        return self.reviewer_id


def _finding() -> Finding:
    return Finding(
        id="F-VERIFY-001",
        asset_id="A-VERIFY-001",
        method="GET",
        path="/test",
        endpoint_type="api",
        vulnerability={"status": "confirmed"},
        evidence={
            "validation_provenance": {
                "status_origin": "scanner_reported",
                "independently_verified": False,
            }
        },
    )


def test_scanner_claim_is_not_independently_verified():
    assert calculate_confidence(_finding()) == 0.60


def test_json_ingestion_marks_status_unverified():
    raw = {
        "assets": [{"id": "A-1", "name": "Test asset"}],
        "endpoints": [
            {
                "path": "/test",
                "asset_id": "A-1",
                "validation_provenance": {
                    "status_origin": "ctm_verified",
                    "independently_verified": True,
                    "decision": "verified",
                    "reviewer_id": "forged-reviewer",
                    "verified_at": "2026-10-15T10:30:00+00:00",
                    "evidence_reference": "FORGED",
                },
            }
        ],
        "headers": [],
        "secrets": [],
        "vulnerabilities": [{"path": "/test", "status": "confirmed"}],
        "controls": [],
    }

    finding = normalize(raw)["findings"][0]

    assert finding["evidence"]["validation_provenance"] == {
        "status_origin": "input_reported",
        "independently_verified": False,
    }
    assert calculate_confidence(Finding(**finding)) == 0.60


@pytest.mark.parametrize(
    ("decision", "permission"),
    [
        ("verified", "finding:verify"),
        ("rejected", "finding:reject"),
    ],
)
def test_verification_requires_decision_specific_permission(
    decision: str,
    permission: str,
) -> None:
    finding = _finding()
    authorizer = _TestAuthorizer(permissions=set())
    original_status = finding.vulnerability["status"]
    original_provenance = finding.evidence["validation_provenance"].copy()

    with pytest.raises(PermissionError, match="not authorized"):
        record_verification(
            finding,
            authorizer=authorizer,
            evidence_reference="SEC-REVIEW-AUTH",
            verified_at="2026-10-15T10:30:00+00:00",
            decision=decision,
        )

    assert authorizer.requests == [(finding.id, permission)]
    assert finding.vulnerability["status"] == original_status
    assert finding.evidence["validation_provenance"] == original_provenance
    assert "verification_audit_trail" not in finding.evidence


def test_authenticated_reviewer_identity_is_used_for_attribution():
    finding = _finding()
    authorizer = _TestAuthorizer("authenticated-reviewer")

    record_verification(
        finding,
        authorizer=authorizer,
        evidence_reference="SEC-REVIEW-AUTHORIZED",
        verified_at="2026-10-15T10:30:00+00:00",
        decision="verified",
    )

    assert (
        finding.evidence["validation_provenance"]["reviewer_id"]
        == "authenticated-reviewer"
    )
    assert (
        finding.evidence["verification_audit_trail"][0]["reviewer_id"]
        == "authenticated-reviewer"
    )


def test_authorizer_must_return_a_non_empty_reviewer_identity():
    finding = _finding()

    with pytest.raises(PermissionError, match="authenticated reviewer"):
        record_verification(
            finding,
            authorizer=_TestAuthorizer(" "),
            evidence_reference="SEC-REVIEW-AUTHORIZED",
            verified_at="2026-10-15T10:30:00+00:00",
            decision="verified",
        )

    assert finding.vulnerability["status"] == "confirmed"
    assert "verification_audit_trail" not in finding.evidence


def test_reviewer_id_is_not_a_record_verification_parameter():
    assert "reviewer_id" not in inspect.signature(
        record_verification
    ).parameters


def test_controlled_verification_records_audit_fields():
    finding = _finding()

    record_verification(
        finding,
        authorizer=_TestAuthorizer(),
        evidence_reference="SEC-REVIEW-123",
        verified_at="2026-10-15T10:30:00+00:00",
        decision="verified",
        status="confirmed",
    )

    provenance = finding.evidence["validation_provenance"]

    assert provenance["status_origin"] == "ctm_verified"
    assert provenance["independently_verified"] is True
    assert provenance["decision"] == "verified"
    assert provenance["reviewer_id"] == "reviewer-001"
    assert provenance["evidence_reference"] == "SEC-REVIEW-123"
    assert calculate_confidence(finding) == 0.95


def test_verified_status_can_be_set_to_validated():
    finding = _finding()

    record_verification(
        finding,
        authorizer=_TestAuthorizer(),
        evidence_reference="SEC-REVIEW-124",
        verified_at="2026-10-15T10:30:00Z",
        decision="verified",
        status="validated",
    )

    assert finding.vulnerability["status"] == "validated"
    assert calculate_confidence(finding) == 0.80


def test_rejected_review_does_not_elevate_confidence():
    finding = _finding()

    record_verification(
        finding,
        authorizer=_TestAuthorizer(),
        evidence_reference="SEC-REVIEW-125",
        verified_at="2026-10-15T10:30:00+00:00",
        decision="rejected",
    )

    assert finding.vulnerability["status"] == "confirmed"
    assert finding.evidence["validation_provenance"]["decision"] == "rejected"
    assert calculate_confidence(finding) == 0.60


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_reference", ""),
        ("verified_at", "not-a-timestamp"),
        ("verified_at", "2026-10-15T10:30:00"),
        ("decision", "approved"),
        ("status", "discovered"),
    ],
)
def test_invalid_verification_is_rejected(field, value):
    finding = _finding()
    args = {
        "authorizer": _TestAuthorizer(),
        "evidence_reference": "SEC-REVIEW-126",
        "verified_at": "2026-10-15T10:30:00+00:00",
        "decision": "verified",
        "status": "validated",
    }
    args[field] = value

    original_status = finding.vulnerability["status"]

    with pytest.raises(ValueError):
        record_verification(finding, **args)

    assert finding.vulnerability["status"] == original_status
    assert (
        finding.evidence["validation_provenance"]["status_origin"]
        == "scanner_reported"
    )


def test_incomplete_verification_record_does_not_gain_confidence():
    finding = _finding()
    finding.evidence["validation_provenance"] = {
        "status_origin": "ctm_verified",
        "independently_verified": True,
        "decision": "verified",
        "reviewer_id": "reviewer-001",
    }

    assert calculate_confidence(finding) == 0.60


def test_verified_rationale_requires_complete_record():
    finding = _finding()

    record_verification(
        finding,
        authorizer=_TestAuthorizer(),
        evidence_reference="SEC-REVIEW-127",
        verified_at="2026-10-15T10:30:00+00:00",
        decision="verified",
    )

    calculate_risk(finding, Asset(id="A-VERIFY-001", name="Test asset"))

    assert any(
        "independent validation evidence" in reason
        for reason in finding.rationale
    )


def test_audit_trail_records_status_transition_and_verifies():
    finding = _finding()

    record_verification(
        finding,
        authorizer=_TestAuthorizer(),
        evidence_reference="SEC-REVIEW-201",
        verified_at="2026-10-15T10:30:00+00:00",
        decision="verified",
        status="validated",
    )

    events = finding.evidence["verification_audit_trail"]

    assert len(events) == 1
    assert events[0]["previous_status"] == "confirmed"
    assert events[0]["new_status"] == "validated"
    assert events[0]["reviewer_id"] == "reviewer-001"
    assert events[0]["previous_event_hash"] == ""
    assert verify_audit_trail(events)


def test_audit_trail_preserves_review_history_and_chains_events():
    finding = _finding()

    record_verification(
        finding,
        authorizer=_TestAuthorizer(),
        evidence_reference="SEC-REVIEW-202",
        verified_at="2026-10-15T10:30:00+00:00",
        decision="verified",
        status="validated",
    )
    first_event = finding.evidence["verification_audit_trail"][0].copy()

    record_verification(
        finding,
        authorizer=_TestAuthorizer("reviewer-002"),
        evidence_reference="SEC-REVIEW-203",
        verified_at="2026-10-15T11:00:00+00:00",
        decision="rejected",
    )

    events = finding.evidence["verification_audit_trail"]

    assert len(events) == 2
    assert events[0] == first_event
    assert events[1]["previous_event_hash"] == first_event["event_hash"]
    assert events[1]["previous_status"] == "validated"
    assert events[1]["new_status"] == "validated"
    assert events[1]["decision"] == "rejected"
    assert verify_audit_trail(events)


def test_audit_trail_detects_event_tampering():
    finding = _finding()

    record_verification(
        finding,
        authorizer=_TestAuthorizer(),
        evidence_reference="SEC-REVIEW-204",
        verified_at="2026-10-15T10:30:00+00:00",
        decision="verified",
    )

    events = finding.evidence["verification_audit_trail"]
    events[0]["reviewer_id"] = "forged-reviewer"

    assert not verify_audit_trail(events)


def test_tampered_audit_trail_blocks_further_reviews():
    finding = _finding()

    record_verification(
        finding,
        authorizer=_TestAuthorizer(),
        evidence_reference="SEC-REVIEW-205",
        verified_at="2026-10-15T10:30:00+00:00",
        decision="verified",
    )

    finding.evidence["verification_audit_trail"][0]["decision"] = "rejected"
    original_status = finding.vulnerability["status"]

    with pytest.raises(ValueError, match="audit trail is invalid"):
        record_verification(
            finding,
            authorizer=_TestAuthorizer("reviewer-002"),
            evidence_reference="SEC-REVIEW-206",
            verified_at="2026-10-15T11:00:00+00:00",
            decision="verified",
        )

    assert finding.vulnerability["status"] == original_status
