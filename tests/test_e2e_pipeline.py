"""End-to-end pipeline tests (Phase 17).

What is covered without a sandbox:
- Upload -> queued job -> worker -> report -> findings, through the real API and worker code.
- File-activity monitoring: a change made inside a temporary directory by this test is seen by
  the snapshot monitor, becomes a behavior event, and is reflected in the risk score with its
  file path as evidence.

What is NOT covered here: running a sample inside the analysis VM. That needs the Phase 4
controller and the VM, so those cases are marked `sandbox` and skipped until they exist.
No sample is executed on the host.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from prometheus_client import REGISTRY
from sqlalchemy import select

from malvax.auth import Role
from malvax.config import Settings
from malvax.correlation import BehaviorType, build_timeline, correlate, from_fs
from malvax.db import AnalysisResult, make_engine, make_session_factory
from malvax.fs_monitor import diff, take_snapshot
from malvax.queue import InMemoryQueue
from malvax.risk import score
from malvax.service import create_analysis, create_user, store_upload
from malvax.worker import process_job

RULES = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture
def pipeline(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'e2e.db').as_posix()}",
        redis_url="redis://unused",
        storage_dir=tmp_path / "storage",
        max_upload_bytes=1024 * 1024,
        rules_dir=RULES,
        jwt_secret="e2e-secret-not-for-production-use",
    )
    factory = make_session_factory(make_engine(settings.database_url))
    with factory() as session:
        create_user(session, "e2e-admin", "e2e-password-1", Role.ADMIN)
    return settings, factory, InMemoryQueue()


def _run(pipeline, payload: bytes, name: str = "lab.elf") -> tuple[str, dict]:
    settings, factory, queue = pipeline
    with factory() as session:
        stored = store_upload(session, io.BytesIO(payload), settings.storage_dir, name,
                              settings.max_upload_bytes)
        job = create_analysis(session, queue, stored.sample.id)
    with factory() as session:
        final = process_job(session, job.id, settings)
    with factory() as session:
        report_row = session.scalars(select(AnalysisResult).where(
            AnalysisResult.job_id == job.id, AnalysisResult.kind == "report")).one()
    return final.value, json.loads(report_row.payload)


@pytest.mark.e2e
def test_upload_to_report_completes_and_is_complete(pipeline) -> None:
    payload = b"\x7fELF" + b"\x01" * 60 + b" http://lab.example.test/a /bin/sh"
    state, report = _run(pipeline, payload)
    assert state == "COMPLETED"
    assert report["schema_version"] == "1.0"
    assert report["sample"]["file_type"] == "ELF"
    # Static-only run: the execution block must be marked as not collected, not empty.
    assert report["execution"], "execution block must exist"
    assert set(report["execution"].values()) == {"NOT_COLLECTED"}
    assert report["limitations"], "limitations section must always be present"
    assert {m["rule_id"] for m in report["static"]["yara"]} >= {"LAB-001", "LAB-002"}


@pytest.mark.e2e
def test_report_findings_all_carry_evidence(pipeline) -> None:
    payload = b"\x7fELF" + b"\x02" * 60 + b" http://lab.example.test/b /bin/sh"
    _, report = _run(pipeline, payload)
    for contribution in report["risk"]["contributions"]:
        assert contribution["points"] > 0
        assert contribution["evidence"], f"no evidence for: {contribution['reason']}"


@pytest.mark.e2e
def test_plain_text_upload_is_unknown_type_and_completes(pipeline) -> None:
    state, report = _run(pipeline, b"just some text MALVAX_LAB_TMP", name="notes.txt")
    assert state == "COMPLETED"
    assert report["sample"]["file_type"] == "UNKNOWN"


@pytest.mark.e2e
def test_file_activity_is_monitored_and_scored(tmp_path: Path) -> None:
    """The test itself writes a file inside its own temporary directory. This checks the
    monitoring path, not a sample: the write is a plain Python call made by this test."""
    watched = tmp_path / "watched"
    watched.mkdir()
    before = take_snapshot(watched)
    (watched / "lab-output.txt").write_bytes(b"written by the test, not by a sample")
    after = take_snapshot(watched)

    fs_events = diff(before, after, timestamp="2026-01-01T00:00:00+00:00")
    assert [e.operation.value for e in fs_events] == ["CREATE"]

    timeline = build_timeline([from_fs(i, e) for i, e in enumerate(fs_events)])
    assert timeline[0].type is BehaviorType.FILE_CREATED
    assert timeline[0].detail["path"] == "lab-output.txt"

    risk = score(timeline=timeline)
    file_points = [c for c in risk.contributions if c.component == "behavior"]
    assert file_points and file_points[0].evidence == (timeline[0].event_id,)


@pytest.mark.e2e
def test_write_then_connect_correlation_end_to_end(tmp_path: Path) -> None:
    from malvax.net_monitor import Connection

    watched = tmp_path / "w"
    watched.mkdir()
    before = take_snapshot(watched)
    (watched / "drop.bin").write_bytes(b"x")
    events = [from_fs(i, e) for i, e in enumerate(
        diff(before, take_snapshot(watched), timestamp="2026-01-01T00:00:01+00:00"))]
    conn = Connection("tcp", "ipv4", "127.0.0.1", 1, "10.0.0.5", 443, "ESTABLISHED", 9,
                      pid=1, process="x")
    from malvax.correlation import from_connection

    events.append(from_connection(99, conn, events[0].time_s + 2.0))
    findings = correlate(build_timeline(events))
    assert any(f.rule == "WRITE_THEN_CONNECT" for f in findings)


@pytest.mark.e2e
def test_metrics_move_during_a_pipeline_run(pipeline) -> None:
    before = REGISTRY.get_sample_value("malvax_analysis_jobs_total", {"state": "COMPLETED"}) or 0
    _run(pipeline, b"\x7fELF" + b"\x03" * 60)
    after = REGISTRY.get_sample_value("malvax_analysis_jobs_total", {"state": "COMPLETED"}) or 0
    assert after == before + 1


@pytest.mark.sandbox
@pytest.mark.skip(reason="Phase 4 sandbox controller and analysis VM not connected yet")
def test_file_activity_sample_in_vm_creates_file_event() -> None:
    """Planned: run lab_samples/file_activity inside the VM and expect a FILE_CREATED event."""


@pytest.mark.sandbox
@pytest.mark.skip(reason="Phase 4 sandbox controller and analysis VM not connected yet")
def test_network_sample_in_vm_records_connection() -> None:
    """Planned: run lab_samples/network_activity against the lab HTTP server inside the VM."""
