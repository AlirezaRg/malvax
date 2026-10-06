import io
from pathlib import Path

from prometheus_client import REGISTRY
from test_api import _auth, _upload, env  # noqa: F401 - shared API fixture

from malvax.auth import Role
from malvax.config import Settings
from malvax.db import make_engine, make_session_factory
from malvax.queue import InMemoryQueue
from malvax.service import create_user, store_upload
from malvax.worker import process_job

RULES = Path(__file__).resolve().parent.parent / "rules"


def _value(name: str, labels: dict[str, str] | None = None) -> float:
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


def test_upload_increments_samples_total(env) -> None:  # noqa: F811 - fixture from test_api
    client, _, _ = env
    before = _value("malvax_samples_total")
    _upload(client, b"\x7fELF" + b"\x0a" * 40)
    assert _value("malvax_samples_total") == before + 1


def test_duplicate_upload_does_not_increment(env) -> None:  # noqa: F811
    client, _, _ = env
    data = b"\x7fELF" + b"\x0b" * 40
    _upload(client, data)
    before = _value("malvax_samples_total")
    _upload(client, data)
    assert _value("malvax_samples_total") == before


def test_queued_and_cancelled_jobs_are_counted(env) -> None:  # noqa: F811
    client, _, _ = env
    headers = _auth(client)
    sample_id = _upload(client, b"\x7fELF" + b"\x0c" * 40, headers=headers).json()["sample"]["id"]
    q_before = _value("malvax_analysis_jobs_total", {"state": "QUEUED"})
    c_before = _value("malvax_analysis_jobs_total", {"state": "CANCELLED"})
    job_id = client.post("/api/v1/analyses", json={"sample_id": sample_id},
                         headers=headers).json()["id"]
    client.post(f"/api/v1/analyses/{job_id}/cancel", headers=headers)
    assert _value("malvax_analysis_jobs_total", {"state": "QUEUED"}) == q_before + 1
    assert _value("malvax_analysis_jobs_total", {"state": "CANCELLED"}) == c_before + 1


def test_worker_completion_records_duration_and_findings(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'm.db').as_posix()}",
        redis_url="redis://unused",
        storage_dir=tmp_path / "storage",
        max_upload_bytes=1024 * 1024,
        rules_dir=RULES,
        jwt_secret="x" * 32,
    )
    factory = make_session_factory(make_engine(settings.database_url))
    queue = InMemoryQueue()
    from malvax.service import create_analysis

    payload = b"\x7fELF" + b"\x0d" * 40 + b" http://lab.example.test/x /bin/sh"
    with factory() as session:
        create_user(session, "m-admin", "metrics-pass-1", Role.ADMIN)
        stored = store_upload(session, io.BytesIO(payload), settings.storage_dir,
                              "m.elf", settings.max_upload_bytes)
        job = create_analysis(session, queue, stored.sample.id)
    completed_before = _value("malvax_analysis_jobs_total", {"state": "COMPLETED"})
    duration_before = _value("malvax_analysis_duration_seconds_count")
    with factory() as session:
        assert process_job(session, job.id, settings).value == "COMPLETED"
    assert _value("malvax_analysis_jobs_total", {"state": "COMPLETED"}) == completed_before + 1
    assert _value("malvax_analysis_duration_seconds_count") == duration_before + 1


def test_worker_failure_is_counted(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'f.db').as_posix()}",
        redis_url="redis://unused",
        storage_dir=tmp_path / "storage",
        max_upload_bytes=1024 * 1024,
        rules_dir=RULES,
        jwt_secret="x" * 32,
    )
    factory = make_session_factory(make_engine(settings.database_url))
    queue = InMemoryQueue()
    from malvax.service import create_analysis

    payload = b"\x7fELF" + b"\x0e" * 40
    with factory() as session:
        stored = store_upload(session, io.BytesIO(payload), settings.storage_dir,
                              "f.elf", settings.max_upload_bytes)
        job = create_analysis(session, queue, stored.sample.id)
    (settings.storage_dir / f"{stored.sample.sha256}.bin").unlink()  # force a stage error
    failed_before = _value("malvax_analysis_failures_total")
    with factory() as session:
        assert process_job(session, job.id, settings).value == "FAILED"
    assert _value("malvax_analysis_failures_total") == failed_before + 1


def test_metrics_endpoint_exposes_counters(env) -> None:  # noqa: F811
    client, _, _ = env
    resp = client.get("/api/v1/metrics")
    assert resp.status_code == 200
    assert "malvax_samples_total" in resp.text
    assert "malvax_analysis_duration_seconds" in resp.text
    assert "malvax_sandbox_timeouts_total" in resp.text
