"""Use cases behind the API: store uploads, create and cancel analysis jobs.

Upload bytes are written to storage without being executed. A file is only read for hashing and
magic-byte checks (malvax.intake). The stored name is the SHA-256, never the uploaded name.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from malvax.auth import InvalidCredentialsError, Role, hash_password, verify_password
from malvax.db import AnalysisJob, Sample, StateTransition, User
from malvax.intake import SampleRejectedError, intake_sample
from malvax.lifecycle import AnalysisState, validate_transition
from malvax.queue import JobQueue

_CHUNK = 1024 * 1024


class NotFoundError(LookupError):
    """Raised when an id does not exist."""


class UsernameTakenError(ValueError):
    """Raised when a username is already registered."""


@dataclass(frozen=True, slots=True)
class StoredUpload:
    sample: Sample
    created: bool


def store_upload(
    session: Session,
    source: BinaryIO,
    storage_dir: Path,
    original_name: str,
    max_bytes: int,
) -> StoredUpload:
    storage_dir.mkdir(parents=True, exist_ok=True)
    part = storage_dir / f"upload-{uuid.uuid4().hex}.part"
    try:
        _copy_limited(source, part, max_bytes)
        meta = intake_sample(part, original_name=original_name, max_bytes=max_bytes)
    except SampleRejectedError:
        part.unlink(missing_ok=True)
        raise
    final = storage_dir / f"{meta.hashes.sha256}.bin"
    existing = session.scalar(select(Sample).where(Sample.sha256 == meta.hashes.sha256))
    if existing is not None:
        part.unlink(missing_ok=True)
        return StoredUpload(sample=existing, created=False)
    part.replace(final)
    sample = Sample(
        id=str(uuid.uuid4()),
        filename=meta.filename,
        size=meta.size,
        sha256=meta.hashes.sha256,
        sha1=meta.hashes.sha1,
        md5=meta.hashes.md5,
        file_type=meta.file_type,
        analysis_status=AnalysisState.SUBMITTED.value,
    )
    session.add(sample)
    session.commit()
    return StoredUpload(sample=sample, created=True)


def create_analysis(session: Session, queue: JobQueue, sample_id: str) -> AnalysisJob:
    sample = session.get(Sample, sample_id)
    if sample is None:
        raise NotFoundError(f"sample {sample_id} not found")
    job = AnalysisJob(id=str(uuid.uuid4()), sample_id=sample.id, state=AnalysisState.QUEUED.value)
    session.add(job)
    session.add(StateTransition(job_id=job.id, from_state=None, to_state=job.state))
    sample.analysis_status = AnalysisState.QUEUED.value
    session.commit()  # the row exists before any worker can see the id
    queue.enqueue(job.id)
    return job


def cancel_analysis(session: Session, job_id: str) -> AnalysisJob:
    job = session.get(AnalysisJob, job_id)
    if job is None:
        raise NotFoundError(f"analysis {job_id} not found")
    current = AnalysisState(job.state)
    validate_transition(current, AnalysisState.CANCELLED)  # raises if already terminal
    session.add(StateTransition(job_id=job.id, from_state=job.state,
                                to_state=AnalysisState.CANCELLED.value))
    job.state = AnalysisState.CANCELLED.value
    job.updated_at = datetime.now(UTC)
    session.commit()
    return job


def _copy_limited(source: BinaryIO, dest: Path, max_bytes: int) -> None:
    """Copy the upload in chunks. Stops as soon as the limit is passed, so a huge upload
    never fills the disk."""
    written = 0
    try:
        with dest.open("wb") as out:
            while chunk := source.read(_CHUNK):
                written += len(chunk)
                if written > max_bytes:
                    raise SampleRejectedError(f"upload exceeds limit of {max_bytes} bytes")
                out.write(chunk)
        if written == 0:
            raise SampleRejectedError("empty upload")
    except SampleRejectedError:
        dest.unlink(missing_ok=True)
        raise



def create_user(session: Session, username: str, password: str, role: Role) -> User:
    username = username.strip()
    if not username:
        raise ValueError("username must not be empty")
    if session.scalar(select(User).where(User.username == username)) is not None:
        raise UsernameTakenError(f"username {username!r} is already taken")
    user = User(id=str(uuid.uuid4()), username=username, password_hash=hash_password(password),
               role=role.value)
    session.add(user)
    session.commit()
    return user


def authenticate_user(session: Session, username: str, password: str) -> User:
    user = session.scalar(select(User).where(User.username == username.strip()))
    # Run the hash check even on a missing user so the response time does not reveal whether
    # the username exists (a constant-time-ish defense, not a strict guarantee).
    reference_hash = user.password_hash if user else _DUMMY_HASH
    valid = verify_password(password, reference_hash)
    if user is None or not valid:
        raise InvalidCredentialsError("invalid username or password")
    return user


_DUMMY_HASH = hash_password("not-a-real-password")
