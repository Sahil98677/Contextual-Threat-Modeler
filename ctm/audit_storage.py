import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from ctm.verification import verify_audit_trail


class SQLiteAuditStore:
    """SQLite-backed append-only storage for per-finding verification events."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS verification_events (
                    finding_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence > 0),
                    event_json TEXT NOT NULL,
                    PRIMARY KEY (finding_id, sequence)
                );

                CREATE TRIGGER IF NOT EXISTS verification_events_no_update
                BEFORE UPDATE ON verification_events
                BEGIN
                    SELECT RAISE(ABORT, 'verification events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS verification_events_no_delete
                BEFORE DELETE ON verification_events
                BEGIN
                    SELECT RAISE(ABORT, 'verification events are append-only');
                END;
                """
            )
            connection.commit()
        if os.name == "posix":
            os.chmod(self.database_path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @staticmethod
    def _validate_finding_id(finding_id: str) -> None:
        if not isinstance(finding_id, str) or not finding_id.strip():
            raise ValueError("finding_id must be a non-empty string")

    def _read_events(
        self,
        connection: sqlite3.Connection,
        finding_id: str,
    ) -> list[dict[str, Any]]:
        rows = connection.execute(
            """
            SELECT sequence, event_json
            FROM verification_events
            WHERE finding_id = ?
            ORDER BY sequence
            """,
            (finding_id,),
        ).fetchall()
        events: list[dict[str, Any]] = []
        for expected_sequence, (sequence, event_json) in enumerate(rows, start=1):
            if sequence != expected_sequence:
                raise ValueError("persistent verification audit sequence is invalid")
            try:
                event = json.loads(event_json)
            except (TypeError, json.JSONDecodeError) as error:
                raise ValueError("persistent verification audit event is invalid") from error
            if not isinstance(event, dict):
                raise TypeError("persistent verification audit event must be an object")
            events.append(event)
        if not verify_audit_trail(events):
            raise ValueError("persistent verification audit trail is invalid")
        return events

    def events_for(self, finding_id: str) -> list[dict[str, Any]]:
        """Load and validate a finding's complete persisted audit history."""
        self._validate_finding_id(finding_id)
        with closing(self._connect()) as connection:
            return self._read_events(connection, finding_id)

    def append_event(self, finding_id: str, event: dict[str, Any]) -> None:
        """Atomically append an event if its hash link extends the stored trail."""
        self._validate_finding_id(finding_id)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            events = self._read_events(connection, finding_id)
            previous_hash = events[-1]["event_hash"] if events else ""
            if event.get("previous_event_hash") != previous_hash:
                raise ValueError("new event does not extend the persistent audit trail")
            if not verify_audit_trail([*events, event]):
                raise ValueError("new verification audit event is invalid")
            event_json = json.dumps(
                event,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            connection.execute(
                """
                INSERT INTO verification_events (finding_id, sequence, event_json)
                VALUES (?, ?, ?)
                """,
                (finding_id, len(events) + 1, event_json),
            )
            connection.commit()
