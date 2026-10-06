"""PostgreSQL-compatible schema for the API layer (SQLAlchemy 2.0).

Works on PostgreSQL in production and SQLite in unit tests. The tables mirror the entities in
docs/architecture.md: samples, analysis_jobs and state_transitions.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    filename: Mapped[str] = mapped_column(String(200))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sha1: Mapped[str] = mapped_column(String(40))
    md5: Mapped[str] = mapped_column(String(32))
    file_type: Mapped[str] = mapped_column(String(20))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    analysis_status: Mapped[str] = mapped_column(String(32), default="SUBMITTED")


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sample_id: Mapped[str] = mapped_column(ForeignKey("samples.id"), index=True)
    state: Mapped[str] = mapped_column(String(32), default="QUEUED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("analysis_jobs.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    payload: Mapped[str] = mapped_column(Text)  # JSON document
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class StateTransition(Base):
    __tablename__ = "state_transitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("analysis_jobs.id"), index=True)
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str] = mapped_column(String(32))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


def make_engine(url: str) -> Engine:
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, pool_pre_ping=True)


def make_session_factory(engine: Engine) -> sessionmaker:
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
