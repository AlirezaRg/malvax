import hashlib
import io
import json
from pathlib import Path

import pytest
from sqlalchemy import select

from malvax.config import Settings
from malvax.db import (
    AnalysisJob,
    AnalysisResult,
    StateTransition,
    make_engine,
    make_session_factory,
)
from malvax.queue import InMemoryQueue
from malvax.service import cancel_analysis, create_analysis, store_upload
from malvax.worker import process_job, run_once

RULES = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture
def ctx(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'worker.db').as_posix()}",
        redis_url="redis://unused",
        storage_dir=tmp_path / "storage",
        max_upload_bytes=1024 * 1024,
        rules_dir=RULES,
    )
    factory = make_session_factory(make_engine(settings.database_url))
    queue = InMemoryQueue()
    yield settings, factory, queue


def _submit(settings, factory, queue, payload: bytes) -> str:
    with factory() as session:
        stored = store_upload(session, io.BytesIO(payload), settings.storage_dir,
                              "sample.elf", settings.max_upload_bytes)
        job = create_analysis(session, queue, stored.sample.id)
        return job.id


def _state(factory, job_id: str) -> AnalysisJob:
    with factory() as session:
        return session.get(AnalysisJob, job_id)


def test_full_static_run_completes_with_report(ctx) -> None:
    settings, factory, queue = ctx
    payload = b"\x7fELF" + b"\x02" * 60 + b" http://lab.example.test/x /bin/sh MALVAX_LAB_TMP"
    job_id = _submit(settings, factory, queue, payload)
    assert run_once(factory, queue, settings) is True
    job = _state(factory, job_id)
    assert job.state == "COMPLETED"
    assert job.error is None
    with factory() as session:
        path = [t.to_state for t in session.scalars(
            select(StateTransition).where(StateTransition.job_id == job_id)
            .order_by(StateTransition.id))]
        report_row = session.scalars(select(AnalysisResult).where(
            AnalysisResult.job_id == job_id, AnalysisResult.kind == "report")).one()
    assert path == ["QUEUED", "STATIC_ANALYSIS", "REPORT_GENERATION", "COMPLETED"]
    report = json.loads(report_row.payload)
    assert report["sample"]["file_type"] == "ELF"
    matched = {m["rule_id"] for m in report["static"]["yara"]}
    assert {"LAB-001", "LAB-002", "LAB-003"} <= matched  # URL, /bin/sh and marker in payload
    assert report["risk"]["total"] > 0


def test_yara_match_reaches_report(ctx) -> None:
    settings, factory, queue = ctx
    payload = b"prefix MALVAX_LAB_TMP suffix"
    job_id = _submit(settings, factory, queue, payload)
    run_once(factory, queue, settings)
    with factory() as session:
        row = session.scalars(select(AnalysisResult).where(
            AnalysisResult.job_id == job_id)).one()
    report = json.loads(row.payload)
    assert [m["rule_id"] for m in report["static"]["yara"]] == ["LAB-003"]


def test_malformed_elf_is_a_finding_not_a_failure(ctx) -> None:
    settings, factory, queue = ctx
    job_id = _submit(settings, factory, queue, b"\x7fELF" + b"\x00" * 10)
    run_once(factory, queue, settings)
    job = _state(factory, job_id)
    assert job.state == "COMPLETED"
    with factory() as session:
        row = session.scalars(select(AnalysisResult).where(
            AnalysisResult.job_id == job_id)).one()
    elf_block = json.loads(row.payload)["static"]["elf"]
    assert "parse_error" in elf_block  # the reason is recorded, not silently dropped


def test_cancelled_before_start_is_skipped(ctx) -> None:
    settings, factory, queue = ctx
    job_id = _submit(settings, factory, queue, b"\x7fELF" + b"\x02" * 40)
    with factory() as session:
        cancel_analysis(session, job_id)
    run_once(factory, queue, settings)
    assert _state(factory, job_id).state == "CANCELLED"
    with factory() as session:
        results = session.scalars(select(AnalysisResult).where(
            AnalysisResult.job_id == job_id)).all()
    assert results == []


def test_missing_stored_file_marks_job_failed_with_reason(ctx) -> None:
    settings, factory, queue = ctx
    payload = b"\x7fELF" + b"\x03" * 40
    job_id = _submit(settings, factory, queue, payload)
    (settings.storage_dir / f"{_sha(payload)}.bin").unlink()
    run_once(factory, queue, settings)
    job = _state(factory, job_id)
    assert job.state == "FAILED"
    assert "FileNotFoundError" in (job.error or "")


def test_empty_queue_returns_false(ctx) -> None:
    settings, factory, queue = ctx
    assert run_once(factory, queue, settings) is False


def test_unknown_job_is_ignored(ctx) -> None:
    settings, factory, _ = ctx
    with factory() as session:
        assert process_job(session, "no-such-job", settings) is None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
