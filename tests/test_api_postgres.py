"""Smoke test of the API against a real PostgreSQL server.

Runs only when MALVAX_TEST_DATABASE_URL is set, for example:
    MALVAX_TEST_DATABASE_URL=postgresql+psycopg://malvax:...@127.0.0.1/malvax
Payloads are random per run, so repeated runs never collide on the unique SHA-256.
"""

import os
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from malvax.api import create_app
from malvax.auth import Role
from malvax.config import Settings
from malvax.db import make_engine, make_session_factory
from malvax.queue import InMemoryQueue
from malvax.service import create_user

DB_URL = os.environ.get("MALVAX_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(not DB_URL, reason="set MALVAX_TEST_DATABASE_URL to run")


def test_full_flow_on_postgresql(tmp_path: Path) -> None:
    assert DB_URL is not None
    queue = InMemoryQueue()
    settings = Settings(database_url=DB_URL, redis_url="redis://unused",
                        storage_dir=tmp_path / "storage", max_upload_bytes=1024 * 1024,
                        rules_dir=Path(__file__).resolve().parent.parent / "rules",
                        jwt_secret="pg-test-secret-not-for-production")
    user = f"pg-{uuid.uuid4().hex[:8]}"
    password = "pgtest-password-1"
    factory = make_session_factory(make_engine(DB_URL))
    with factory() as session:
        create_user(session, user, password, Role.ADMIN)
    with TestClient(create_app(settings, queue=queue)) as client:
        assert client.get("/api/v1/health").json()["database"] is True
        login = client.post("/api/v1/auth/login", json={"username": user, "password": password})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        payload = b"\x7fELF" + uuid.uuid4().bytes
        upload = client.post("/api/v1/samples",
                             files={"file": ("pg.elf", payload, "application/octet-stream")},
                             headers=headers)
        assert upload.status_code == 201
        sample_id = upload.json()["sample"]["id"]
        job = client.post("/api/v1/analyses", json={"sample_id": sample_id}, headers=headers)
        assert job.status_code == 202
        job_id = job.json()["id"]
        assert client.get(f"/api/v1/analyses/{job_id}", headers=headers).json()["state"] == "QUEUED"
        cancel = client.post(f"/api/v1/analyses/{job_id}/cancel", headers=headers)
        assert cancel.json()["state"] == "CANCELLED"
