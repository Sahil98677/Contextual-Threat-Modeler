import json
import sqlite3

import pytest

from ctm.audit_storage import SQLiteAuditStore
from ctm.models import Finding
from ctm.verification import record_verification


class _Authorizer:
    def authorize(self, finding_id: str, permission: str) -> str:
        return "storage-test-reviewer"


def _finding() -> Finding:
    return Finding(
        id="F-AUDIT-STORAGE-001",
        asset_id="A-AUDIT-STORAGE-001",
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


def _record(finding: Finding, store: SQLiteAuditStore) -> None:
    record_verification(
        finding,
        authorizer=_Authorizer(),
        audit_store=store,
        evidence_reference="SEC-REVIEW-STORAGE",
        verified_at="2026-10-15T10:30:00+00:00",
        decision="verified",
        status="validated",
    )


def test_sqlite_insert_failure_does_not_mutate_finding_and_can_recover(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    finding = _finding()
    original_provenance = finding.evidence["validation_provenance"].copy()

    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_verification_insert
            BEFORE INSERT ON verification_events
            BEGIN
                SELECT RAISE(ABORT, 'simulated SQLite write failure');
            END;
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="simulated SQLite write failure"):
        _record(finding, store)

    assert finding.vulnerability["status"] == "confirmed"
    assert finding.evidence["validation_provenance"] == original_provenance
    assert "verification_audit_trail" not in finding.evidence
    assert store.events_for(finding.id) == []

    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DROP TRIGGER fail_verification_insert")

    _record(finding, store)
    assert finding.vulnerability["status"] == "validated"
    assert len(store.events_for(finding.id)) == 1


def test_corrupt_sqlite_event_json_blocks_history_reads(tmp_path):
    store = SQLiteAuditStore(tmp_path / "corrupt-audit.sqlite3")
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            INSERT INTO verification_events (finding_id, sequence, event_json)
            VALUES (?, ?, ?)
            """,
            ("F-AUDIT-STORAGE-001", 1, "{not-json"),
        )

    with pytest.raises(ValueError, match="persistent verification audit event is invalid"):
        store.events_for("F-AUDIT-STORAGE-001")


def test_sqlite_sequence_gap_blocks_history_reads(tmp_path):
    store = SQLiteAuditStore(tmp_path / "sequence-audit.sqlite3")
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            INSERT INTO verification_events (finding_id, sequence, event_json)
            VALUES (?, ?, ?)
            """,
            ("F-AUDIT-STORAGE-001", 2, json.dumps({})),
        )

    with pytest.raises(ValueError, match="persistent verification audit sequence"):
        store.events_for("F-AUDIT-STORAGE-001")


def test_sqlite_append_rejects_broken_chain_without_writing(tmp_path):
    store = SQLiteAuditStore(tmp_path / "chain-audit.sqlite3")
    finding = _finding()
    _record(finding, store)
    events_before = store.events_for(finding.id)
    broken_event = events_before[0].copy()
    broken_event["previous_event_hash"] = "wrong-link"

    with pytest.raises(ValueError, match="does not extend the persistent audit trail"):
        store.append_event(finding.id, broken_event)

    assert store.events_for(finding.id) == events_before


def test_sqlite_connection_error_is_reported(tmp_path):
    database_path = tmp_path / "not-a-database-file"
    database_path.mkdir()

    with pytest.raises(sqlite3.OperationalError, match="unable to open database file"):
        SQLiteAuditStore(database_path)
