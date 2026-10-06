import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from malvax.api import create_app
from malvax.auth import Role
from malvax.config import Settings
from malvax.db import make_engine, make_session_factory
from malvax.queue import InMemoryQueue
from malvax.service import create_user

ELF_BYTES = b"\x7fELF" + b"\x02" * 60
JWT_SECRET = "test-secret-not-for-production-0123456789"


@pytest.fixture
def env(tmp_path: Path):
    queue = InMemoryQueue()
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'api.db').as_posix()}",
        redis_url="redis://unused",
        storage_dir=tmp_path / "storage",
        max_upload_bytes=1024,
        rules_dir=Path(__file__).resolve().parent.parent / "rules",
        jwt_secret=JWT_SECRET,
    )
    factory = make_session_factory(make_engine(settings.database_url))
    with factory() as session:
        create_user(session, "admin", "adminpass123", Role.ADMIN)
        create_user(session, "analyst", "analystpass123", Role.ANALYST)
        create_user(session, "viewer", "viewerpass123", Role.VIEWER)
    app = create_app(settings, queue=queue)
    with TestClient(app) as client:
        yield client, queue, settings


def _token(client: TestClient, username: str, password: str) -> str:
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth(client: TestClient, username: str = "analyst", password: str = "analystpass123"):
    return {"Authorization": f"Bearer {_token(client, username, password)}"}


def _upload(client: TestClient, data: bytes, name: str = "suspect.elf", headers=None):
    headers = headers if headers is not None else _auth(client)
    return client.post(
        "/api/v1/samples",
        files={"file": (name, data, "application/octet-stream")},
        headers=headers,
    )


def test_health_is_public_and_needs_no_token(env) -> None:
    client, _, _ = env
    body = client.get("/api/v1/health").json()
    assert body == {"status": "ok", "database": True, "queue": True}


def test_login_with_wrong_password_is_401(env) -> None:
    client, _, _ = env
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "nope12345"})
    assert resp.status_code == 401


def test_login_with_unknown_user_is_401(env) -> None:
    client, _, _ = env
    resp = client.post("/api/v1/auth/login", json={"username": "ghost", "password": "whatever1"})
    assert resp.status_code == 401


def test_login_returns_role_and_bearer_token(env) -> None:
    client, _, _ = env
    resp = client.post(
        "/api/v1/auth/login", json={"username": "viewer", "password": "viewerpass123"}
    )
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "viewer"
    assert len(body["access_token"]) > 20


def test_protected_endpoint_without_token_is_401(env) -> None:
    client, _, _ = env
    assert client.get("/api/v1/samples").status_code == 401


def test_protected_endpoint_with_garbage_token_is_401(env) -> None:
    client, _, _ = env
    resp = client.get("/api/v1/samples", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_viewer_cannot_upload_but_can_list(env) -> None:
    client, _, _ = env
    viewer = _auth(client, "viewer", "viewerpass123")
    assert _upload(client, ELF_BYTES, headers=viewer).status_code == 403
    assert client.get("/api/v1/samples", headers=viewer).status_code == 200


def test_analyst_cannot_manage_users(env) -> None:
    client, _, _ = env
    resp = client.post(
        "/api/v1/users",
        json={"username": "new", "password": "newpassword1", "role": "viewer"},
        headers=_auth(client),
    )
    assert resp.status_code == 403


def test_admin_can_create_user_who_can_then_log_in(env) -> None:
    client, _, _ = env
    admin = _auth(client, "admin", "adminpass123")
    created = client.post(
        "/api/v1/users",
        json={"username": "newanalyst", "password": "newpassword1", "role": "analyst"},
        headers=admin,
    )
    assert created.status_code == 201
    assert created.json()["role"] == "analyst"
    assert _token(client, "newanalyst", "newpassword1")


def test_duplicate_username_is_409(env) -> None:
    client, _, _ = env
    admin = _auth(client, "admin", "adminpass123")
    resp = client.post(
        "/api/v1/users",
        json={"username": "admin", "password": "whatever12", "role": "viewer"},
        headers=admin,
    )
    assert resp.status_code == 409


def test_upload_stores_by_sha256_and_returns_metadata(env) -> None:
    client, _, settings = env
    resp = _upload(client, ELF_BYTES)
    assert resp.status_code == 201
    sample = resp.json()["sample"]
    assert resp.json()["created"] is True
    assert sample["file_type"] == "ELF"
    assert len(sample["sha256"]) == 64
    assert (settings.storage_dir / f"{sample['sha256']}.bin").read_bytes() == ELF_BYTES


def test_duplicate_upload_returns_same_sample(env) -> None:
    client, _, _ = env
    headers = _auth(client)
    first = _upload(client, ELF_BYTES, headers=headers).json()["sample"]
    second = _upload(client, ELF_BYTES, headers=headers).json()
    assert second["created"] is False
    assert second["sample"]["id"] == first["id"]


def test_stored_name_is_sanitized_not_the_uploaded_path(env) -> None:
    client, _, _ = env
    sample = _upload(client, ELF_BYTES, name="../../etc/passwd").json()["sample"]
    assert sample["filename"] == "passwd"


def test_oversized_upload_rejected_and_no_partial_file_left(env) -> None:
    client, _, settings = env
    resp = _upload(client, b"A" * 2048)
    assert resp.status_code == 422
    assert "limit" in resp.json()["detail"]
    leftovers = list(settings.storage_dir.glob("*.part")) if settings.storage_dir.exists() else []
    assert leftovers == []


def test_empty_upload_rejected(env) -> None:
    client, _, _ = env
    assert _upload(client, b"").status_code == 422


def test_list_and_get_sample(env) -> None:
    client, _, _ = env
    headers = _auth(client)
    sample_id = _upload(client, ELF_BYTES, headers=headers).json()["sample"]["id"]
    listed = client.get("/api/v1/samples", headers=headers).json()
    assert [s["id"] for s in listed] == [sample_id]
    assert client.get(f"/api/v1/samples/{sample_id}", headers=headers).status_code == 200


def test_unknown_sample_is_404(env) -> None:
    client, _, _ = env
    assert client.get("/api/v1/samples/does-not-exist", headers=_auth(client)).status_code == 404


def test_start_analysis_queues_job(env) -> None:
    client, queue, _ = env
    headers = _auth(client)
    sample_id = _upload(client, ELF_BYTES, headers=headers).json()["sample"]["id"]
    resp = client.post("/api/v1/analyses", json={"sample_id": sample_id}, headers=headers)
    assert resp.status_code == 202
    job = resp.json()
    assert job["state"] == "QUEUED"
    assert list(queue.items) == [job["id"]]
    assert client.get(f"/api/v1/analyses/{job['id']}", headers=headers).json()["state"] == "QUEUED"


def test_analysis_for_missing_sample_is_404(env) -> None:
    client, queue, _ = env
    headers = _auth(client)
    resp = client.post("/api/v1/analyses", json={"sample_id": "nope"}, headers=headers)
    assert resp.status_code == 404
    assert list(queue.items) == []


def test_cancel_then_second_cancel_conflicts(env) -> None:
    client, _, _ = env
    headers = _auth(client)
    sample_id = _upload(client, ELF_BYTES, headers=headers).json()["sample"]["id"]
    job_id = client.post(
        "/api/v1/analyses", json={"sample_id": sample_id}, headers=headers
    ).json()["id"]
    cancelled = client.post(f"/api/v1/analyses/{job_id}/cancel", headers=headers)
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "CANCELLED"
    assert client.post(f"/api/v1/analyses/{job_id}/cancel", headers=headers).status_code == 409


def test_cancel_unknown_job_is_404(env) -> None:
    client, _, _ = env
    resp = client.post("/api/v1/analyses/missing/cancel", headers=_auth(client))
    assert resp.status_code == 404


def _complete_job(settings: Settings, job_id: str) -> None:
    from malvax.worker import process_job

    factory = make_session_factory(make_engine(settings.database_url))
    with factory() as session:
        process_job(session, job_id, settings)


def test_report_endpoint_returns_completed_report(env) -> None:
    client, _, settings = env
    headers = _auth(client)
    sample_id = _upload(
        client, b"\x7fELF" + b"\x02" * 60 + b" /bin/sh", headers=headers
    ).json()["sample"]["id"]
    job_id = client.post(
        "/api/v1/analyses", json={"sample_id": sample_id}, headers=headers
    ).json()["id"]
    _complete_job(settings, job_id)
    findings = client.get("/api/v1/findings", params={"analysis_id": job_id}, headers=headers)
    assert findings.status_code == 200
    body = findings.json()
    report = client.get(f"/api/v1/reports/{body['report_id']}", headers=headers)
    assert report.status_code == 200
    assert report.json()["sample"]["file_type"] == "ELF"
    assert body["yara_matches"] and {"LAB-002"} <= {m["rule_id"] for m in body["yara_matches"]}


def test_report_unknown_id_is_404(env) -> None:
    client, _, _ = env
    resp = client.get("/api/v1/reports/999999", headers=_auth(client))
    assert resp.status_code == 404


def test_findings_without_report_is_404(env) -> None:
    client, _, _ = env
    headers = _auth(client)
    sample_id = _upload(client, b"\x7fELF" + b"\x02" * 60, headers=headers).json()["sample"]["id"]
    job_id = client.post(
        "/api/v1/analyses", json={"sample_id": sample_id}, headers=headers
    ).json()["id"]
    resp = client.get("/api/v1/findings", params={"analysis_id": job_id}, headers=headers)
    assert resp.status_code == 404


def test_cors_allows_frontend_origin(env) -> None:
    client, _, _ = env
    resp = client.get("/api/v1/health", headers={"Origin": "http://localhost:3000"})
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_analyses_list_returns_recent_jobs_first(env) -> None:
    client, _, _ = env
    headers = _auth(client)
    sample_id = _upload(client, b"\x7fELF" + b"\x05" * 40, headers=headers).json()["sample"]["id"]
    first = client.post(
        "/api/v1/analyses", json={"sample_id": sample_id}, headers=headers
    ).json()["id"]
    time.sleep(0.05)  # Windows clock resolution is coarse; keep the two timestamps distinct
    second = client.post(
        "/api/v1/analyses", json={"sample_id": sample_id}, headers=headers
    ).json()["id"]
    ids = [j["id"] for j in client.get("/api/v1/analyses", headers=headers).json()]
    assert ids.index(second) < ids.index(first)
