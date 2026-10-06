"""SQLite-backed sample and lifecycle store (Phase 1).

SQLite is a stand-in for the PostgreSQL schema in docs/architecture.md so Phase 1 runs
without a server. The SQL is kept portable; migrating to PostgreSQL is a Phase 12 task.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from malvax.intake import SampleMetadata
from malvax.lifecycle import AnalysisState, validate_transition

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    sha1 TEXT NOT NULL,
    md5 TEXT NOT NULL,
    file_type TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    analysis_status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id TEXT NOT NULL REFERENCES samples(id),
    from_state TEXT,
    to_state TEXT NOT NULL,
    changed_at TEXT NOT NULL
);
"""


@dataclass(frozen=True, slots=True)
class StoredSample:
    id: str
    filename: str
    size: int
    sha256: str
    sha1: str
    md5: str
    file_type: str
    uploaded_at: str
    analysis_status: AnalysisState


class SampleStore:
    def __init__(self, db_path: Path | str) -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def add_sample(self, meta: SampleMetadata) -> StoredSample:
        """Insert a sample. Returns the existing row if the SHA-256 is already known."""
        existing = self.get_by_sha256(meta.hashes.sha256)
        if existing is not None:
            return existing
        sample_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with self._conn:
            self._conn.execute(
                "INSERT INTO samples (id, filename, size, sha256, sha1, md5, file_type, "
                "uploaded_at, analysis_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sample_id,
                    meta.filename,
                    meta.size,
                    meta.hashes.sha256,
                    meta.hashes.sha1,
                    meta.hashes.md5,
                    meta.file_type,
                    now,
                    AnalysisState.SUBMITTED.value,
                ),
            )
            self._conn.execute(
                "INSERT INTO state_transitions (sample_id, from_state, to_state, changed_at) "
                "VALUES (?, NULL, ?, ?)",
                (sample_id, AnalysisState.SUBMITTED.value, now),
            )
        sample = self.get(sample_id)
        assert sample is not None
        return sample

    def get(self, sample_id: str) -> StoredSample | None:
        row = self._conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
        return _to_sample(row) if row else None

    def get_by_sha256(self, sha256: str) -> StoredSample | None:
        row = self._conn.execute("SELECT * FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
        return _to_sample(row) if row else None

    def transition(self, sample_id: str, nxt: AnalysisState) -> None:
        """Move a sample to a new state; illegal transitions raise InvalidTransitionError."""
        sample = self.get(sample_id)
        if sample is None:
            raise KeyError(f"unknown sample {sample_id}")
        validate_transition(sample.analysis_status, nxt)
        now = datetime.now(UTC).isoformat()
        with self._conn:
            self._conn.execute(
                "UPDATE samples SET analysis_status = ? WHERE id = ?", (nxt.value, sample_id)
            )
            self._conn.execute(
                "INSERT INTO state_transitions (sample_id, from_state, to_state, changed_at) "
                "VALUES (?, ?, ?, ?)",
                (sample_id, sample.analysis_status.value, nxt.value, now),
            )

    def transitions(self, sample_id: str) -> list[tuple[str | None, str]]:
        rows = self._conn.execute(
            "SELECT from_state, to_state FROM state_transitions WHERE sample_id = ? ORDER BY id",
            (sample_id,),
        ).fetchall()
        return [(r["from_state"], r["to_state"]) for r in rows]


def _to_sample(row: sqlite3.Row) -> StoredSample:
    return StoredSample(
        id=row["id"],
        filename=row["filename"],
        size=row["size"],
        sha256=row["sha256"],
        sha1=row["sha1"],
        md5=row["md5"],
        file_type=row["file_type"],
        uploaded_at=row["uploaded_at"],
        analysis_status=AnalysisState(row["analysis_status"]),
    )
