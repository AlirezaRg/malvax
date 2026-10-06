"""REST API (Phases 12 and 14).

Endpoints:
    GET    /api/v1/health                          public, no auth
    POST   /api/v1/auth/login                       JSON {"username", "password"} -> JWT
    POST   /api/v1/users                            admin only: create a user
    POST   /api/v1/samples                          analyst/admin, multipart field "file"
    GET    /api/v1/samples                          any role
    GET    /api/v1/samples/{sample_id}               any role
    POST   /api/v1/analyses                         analyst/admin, JSON {"sample_id": "..."}
    GET    /api/v1/analyses                         any role
    GET    /api/v1/analyses/{job_id}                 any role
    POST   /api/v1/analyses/{job_id}/cancel          analyst/admin
    GET    /api/v1/reports/{report_id}               any role
    GET    /api/v1/findings?analysis_id=...          any role

Every endpoint except health and login requires "Authorization: Bearer <token>" from
POST /api/v1/auth/login. Tokens are JWTs signed with MALVAX_JWT_SECRET and expire after
ACCESS_TOKEN_TTL_MINUTES (malvax/auth.py). There is no user self-registration: an existing
admin creates accounts through POST /api/v1/users.

Long-running analysis never runs inside a request. The API only queues a job.
"""



import json
import logging
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from malvax import metrics
from malvax.ai_analyst import (
    AnalystOutputError,
    AnalystProvider,
    OfflineProvider,
    analyze_report,
)
from malvax.ai_remote import AnthropicProvider, RemoteProviderError
from malvax.auth import (
    InvalidCredentialsError,
    InvalidTokenError,
    Role,
    TokenPayload,
    create_access_token,
    decode_access_token,
    role_allows,
)
from malvax.config import Settings
from malvax.db import AnalysisJob, AnalysisResult, Sample, make_engine, make_session_factory
from malvax.intake import SampleRejectedError
from malvax.lifecycle import InvalidTransitionError
from malvax.queue import JobQueue, RedisQueue
from malvax.service import (
    NotFoundError,
    UsernameTakenError,
    authenticate_user,
    cancel_analysis,
    create_analysis,
    create_user,
    store_upload,
)


@dataclass(slots=True)
class AppState:
    settings: Settings
    session_factory: sessionmaker
    queue: JobQueue


class AnalysisRequest(BaseModel):
    sample_id: str


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: Role


def create_app(settings: Settings | None = None, queue: JobQueue | None = None) -> FastAPI:
    cfg = settings or Settings.from_env()
    if not cfg.jwt_secret:
        # Dev fallback only: a secret generated per process means every existing token is
        # invalidated on restart. Production deployments must set MALVAX_JWT_SECRET.
        logging.getLogger("malvax.api").warning(
            "MALVAX_JWT_SECRET not set; using a random per-process secret"
        )
        cfg = Settings(cfg.database_url, cfg.redis_url, cfg.storage_dir, cfg.max_upload_bytes,
                       cfg.rules_dir, cfg.cors_origins, secrets.token_hex(32))
    engine = make_engine(cfg.database_url)
    state = AppState(
        settings=cfg,
        session_factory=make_session_factory(engine),
        queue=queue or _redis_queue(cfg.redis_url),
    )
    app = FastAPI(title="MalvaX API", version="0.12.0")
    app.state.malvax = state
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cfg.cors_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    def get_session(request: Request) -> Iterator[Session]:
        session: Session = request.app.state.malvax.session_factory()
        try:
            yield session
        finally:
            session.close()

    SessionDep = Annotated[Session, Depends(get_session)]
    bearer = HTTPBearer(auto_error=False)

    def get_current_user(
        creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> TokenPayload:
        if creds is None:
            raise HTTPException(status_code=401, detail="missing bearer token")
        try:
            return decode_access_token(creds.credentials, cfg.jwt_secret)
        except InvalidTokenError as exc:
            raise HTTPException(status_code=401, detail=f"invalid token: {exc}") from exc

    def require(permission: str):
        def check(user: Annotated[TokenPayload, Depends(get_current_user)]) -> TokenPayload:
            if not role_allows(user.role, permission):
                raise HTTPException(status_code=403, detail=f"role {user.role.value} cannot "
                                                             f"{permission}")
            return user
        return check

    ViewReports = Annotated[TokenPayload, Depends(require("view_reports"))]
    SubmitSamples = Annotated[TokenPayload, Depends(require("submit_samples"))]
    StartAnalysis = Annotated[TokenPayload, Depends(require("start_analysis"))]
    ManageUsers = Annotated[TokenPayload, Depends(require("manage_users"))]

    @app.get("/api/v1/metrics")
    def prometheus_metrics() -> Response:
        """Prometheus scrape endpoint. Exposes counters only, no sample content or secrets."""
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/api/v1/health")
    def health() -> dict[str, object]:
        db_ok = True
        try:
            with state.session_factory() as s:
                s.execute(select(1))
        except Exception:  # noqa: BLE001 - health must report, not crash
            db_ok = False
        return {"status": "ok" if db_ok else "degraded", "database": db_ok,
                "queue": state.queue.ping()}

    @app.post("/api/v1/auth/login")
    def login(body: LoginRequest, session: SessionDep) -> dict[str, object]:
        try:
            user = authenticate_user(session, body.username, body.password)
        except InvalidCredentialsError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        token = create_access_token(user.id, user.username, Role(user.role), cfg.jwt_secret)
        return {"access_token": token, "token_type": "bearer", "role": user.role}

    @app.post("/api/v1/users", status_code=201)
    def add_user(body: CreateUserRequest, session: SessionDep, _: ManageUsers) -> dict[str, object]:
        try:
            user = create_user(session, body.username, body.password, body.role)
        except UsernameTakenError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"id": user.id, "username": user.username, "role": user.role}

    @app.post("/api/v1/samples", status_code=201)
    def upload_sample(file: UploadFile, session: SessionDep, _: SubmitSamples) -> dict[str, object]:
        try:
            stored = store_upload(
                session, file.file, cfg.storage_dir,
                original_name=file.filename or "sample.bin",
                max_bytes=cfg.max_upload_bytes,
            )
        except SampleRejectedError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if stored.created:
            metrics.SAMPLES_TOTAL.inc()
        return {"created": stored.created, "sample": _sample_dict(stored.sample)}

    @app.get("/api/v1/samples")
    def list_samples(
        session: SessionDep, _: ViewReports, limit: int = 50
    ) -> list[dict[str, object]]:
        rows = session.scalars(select(Sample).order_by(Sample.uploaded_at.desc()).limit(
            min(max(limit, 1), 200)))
        return [_sample_dict(s) for s in rows]

    @app.get("/api/v1/samples/{sample_id}")
    def get_sample(sample_id: str, session: SessionDep, _: ViewReports) -> dict[str, object]:
        sample = session.get(Sample, sample_id)
        if sample is None:
            raise HTTPException(status_code=404, detail="sample not found")
        return _sample_dict(sample)

    @app.post("/api/v1/analyses", status_code=202)
    def start_analysis(body: AnalysisRequest, session: SessionDep,
                       _: StartAnalysis) -> dict[str, object]:
        try:
            job = create_analysis(session, state.queue, body.sample_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        metrics.ANALYSIS_JOBS_TOTAL.labels(state="QUEUED").inc()
        return _job_dict(job)

    @app.get("/api/v1/analyses")
    def list_analyses(
        session: SessionDep, _: ViewReports, limit: int = 50
    ) -> list[dict[str, object]]:
        rows = session.scalars(
            select(AnalysisJob)
            .order_by(AnalysisJob.created_at.desc())
            .limit(min(max(limit, 1), 200))
        )
        return [_job_dict(j) for j in rows]

    @app.get("/api/v1/analyses/{job_id}")
    def get_analysis(job_id: str, session: SessionDep, _: ViewReports) -> dict[str, object]:
        job = session.get(AnalysisJob, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="analysis not found")
        return _job_dict(job)

    @app.post("/api/v1/analyses/{job_id}/cancel")
    def cancel(job_id: str, session: SessionDep, _: StartAnalysis) -> dict[str, object]:
        try:
            job = cancel_analysis(session, job_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except InvalidTransitionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        metrics.ANALYSIS_JOBS_TOTAL.labels(state="CANCELLED").inc()
        return _job_dict(job)

    @app.get("/api/v1/reports/{report_id}")
    def get_report(report_id: int, session: SessionDep, _: ViewReports) -> dict[str, object]:
        row = session.get(AnalysisResult, report_id)
        if row is None or row.kind != "report":
            raise HTTPException(status_code=404, detail="report not found")
        return json.loads(row.payload)

    @app.get("/api/v1/analyses/{job_id}/ai-summary")
    def ai_summary(job_id: str, session: SessionDep, _: ViewReports) -> dict[str, object]:
        """AI-assisted summary of the latest report. Structured evidence only; see ai_analyst."""
        row = session.scalars(
            select(AnalysisResult)
            .where(AnalysisResult.job_id == job_id, AnalysisResult.kind == "report")
            .order_by(AnalysisResult.id.desc())
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="no report for this analysis")
        report = json.loads(row.payload)
        provider = _analyst_provider(cfg)
        try:
            summary = analyze_report(report, provider)
        except AnalystOutputError as exc:
            # The provider output was rejected by validation. Do not echo it back.
            raise HTTPException(status_code=502, detail="analyst output rejected") from exc
        except RemoteProviderError as exc:
            raise HTTPException(status_code=502, detail="analyst provider unavailable") from exc
        finally:
            if isinstance(provider, AnthropicProvider):
                provider.close()
        summary["report_id"] = row.id
        return summary

    @app.get("/api/v1/findings")
    def list_findings(analysis_id: str, session: SessionDep, _: ViewReports) -> dict[str, object]:
        """Findings of the latest report for one analysis.

        Static-only until the dynamic path exists.
        """
        row = session.scalars(
            select(AnalysisResult)
            .where(AnalysisResult.job_id == analysis_id, AnalysisResult.kind == "report")
            .order_by(AnalysisResult.id.desc())
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="no report for this analysis")
        report = json.loads(row.payload)
        risk = report.get("risk")
        contributions = risk["contributions"] if isinstance(risk, dict) else []
        yara = report.get("static", {}).get("yara")
        return {
            "analysis_id": analysis_id,
            "report_id": row.id,
            "risk_contributions": contributions,
            "yara_matches": yara if isinstance(yara, list) else [],
        }

    return app


def _analyst_provider(cfg: Settings) -> AnalystProvider:
    if cfg.ai_provider == "anthropic":
        return AnthropicProvider(cfg.anthropic_api_key)
    return OfflineProvider()


def _redis_queue(redis_url: str) -> JobQueue:
    """Production queue. The API and the worker must share Redis, or jobs never reach the worker."""
    import redis

    return RedisQueue(redis.Redis.from_url(redis_url))


def _sample_dict(sample: Sample) -> dict[str, object]:
    return {
        "id": sample.id,
        "filename": sample.filename,
        "size": sample.size,
        "sha256": sample.sha256,
        "sha1": sample.sha1,
        "md5": sample.md5,
        "file_type": sample.file_type,
        "uploaded_at": sample.uploaded_at.isoformat(),
        "analysis_status": sample.analysis_status,
    }


def _job_dict(job: AnalysisJob) -> dict[str, object]:
    return {
        "id": job.id,
        "sample_id": job.sample_id,
        "state": job.state,
        "created_at": job.created_at.isoformat(),
        "updated_at": job.updated_at.isoformat(),
    }
