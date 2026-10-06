"""Background analysis worker (Phase 12).

Pops job ids from the queue, runs the static pipeline on the stored sample, and records every
state change. Errors mark the job FAILED with the reason. A job cancelled before it starts is
skipped.

Static-only path: STATIC_ANALYSIS -> REPORT_GENERATION -> COMPLETED. The dynamic path
(SANDBOX_PREPARATION onward) is not connected yet, so the report says so explicitly.

Run it with:  python -m malvax.worker
"""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime

import prometheus_client
from sqlalchemy.orm import Session, sessionmaker

from malvax import metrics
from malvax.config import Settings
from malvax.db import (
    AnalysisJob,
    AnalysisResult,
    Sample,
    StateTransition,
    make_engine,
    make_session_factory,
)
from malvax.elf import ElfParseError, analyze_elf
from malvax.lifecycle import AnalysisState, validate_transition
from malvax.queue import JobQueue, RedisQueue
from malvax.report import build_report, to_json
from malvax.risk import score
from malvax.strings_analysis import analyze_strings
from malvax.yara_scan import compile_rules, scan_bytes

log = logging.getLogger("malvax.worker")
MAX_ERROR_CHARS = 500
RETRY_DELAY_S = 2.0


def process_job(session: Session, job_id: str, settings: Settings) -> AnalysisState | None:
    """Run one job to a terminal state. Returns the final state, or None if the job is unknown."""
    job = session.get(AnalysisJob, job_id)
    if job is None:
        log.warning("job %s not found; skipping", job_id)
        return None
    if job.state == AnalysisState.CANCELLED.value:
        return AnalysisState.CANCELLED
    sample = session.get(Sample, job.sample_id)
    if sample is None:
        return _fail(session, job, "sample row missing")
    started = time.monotonic()
    metrics.WORKER_ACTIVE.inc()
    try:
        _advance(session, job, sample, AnalysisState.STATIC_ANALYSIS)
        results = _static_stage(settings, sample)
        _advance(session, job, sample, AnalysisState.REPORT_GENERATION)
        report = _assemble_report(sample, results)
        session.add(AnalysisResult(job_id=job.id, kind="report", payload=to_json(report)))
        _advance(session, job, sample, AnalysisState.COMPLETED)
    except Exception as exc:  # noqa: BLE001 - any stage error must end the job, not the worker
        session.rollback()
        job = session.get(AnalysisJob, job_id)
        metrics.ANALYSIS_FAILURES_TOTAL.inc()
        return _fail(session, job, f"{type(exc).__name__}: {exc}")
    finally:
        metrics.WORKER_ACTIVE.dec()
    metrics.ANALYSIS_DURATION_SECONDS.observe(time.monotonic() - started)
    metrics.FINDINGS_TOTAL.inc(len(report["risk"]["contributions"]))
    metrics.ANALYSIS_JOBS_TOTAL.labels(state="COMPLETED").inc()
    return AnalysisState.COMPLETED


def run_once(session_factory: sessionmaker, queue: JobQueue, settings: Settings,
             timeout_s: float = 1.0) -> bool:
    """Take one job from the queue and process it. Returns False if the queue was empty."""
    job_id = queue.dequeue(timeout_s)
    if job_id is None:
        return False
    with session_factory() as session:
        state = process_job(session, job_id, settings)
        log.info("job %s finished in state %s", job_id, state)
    return True


def run_forever(session_factory: sessionmaker, queue: JobQueue, settings: Settings) -> None:
    """Keep serving jobs. A transient Redis or database error is logged and retried after a
    pause, so one network blip does not stop the worker."""
    while True:
        try:
            run_once(session_factory, queue, settings, timeout_s=5.0)
        except Exception:  # noqa: BLE001 - keep the worker alive; the error is logged
            log.exception("worker loop error; retrying in %ss", RETRY_DELAY_S)
            time.sleep(RETRY_DELAY_S)


def _static_stage(settings: Settings, sample: Sample) -> dict[str, object]:
    path = settings.storage_dir / f"{sample.sha256}.bin"
    data = path.read_bytes()
    elf = None
    elf_error = None
    if sample.file_type == "ELF":
        try:
            elf = analyze_elf(path)
        except ElfParseError as exc:
            # A malformed ELF is a finding about the file, not a worker failure.
            elf = None
            elf_error = str(exc)
            log.info("ELF parse failed for %s: %s", sample.sha256, exc)
    strings = analyze_strings(data)
    rules = compile_rules(settings.rules_dir)
    yara = scan_bytes(rules, data)
    return {"elf": elf, "elf_error": elf_error, "strings": strings, "yara": yara}


def _assemble_report(sample: Sample, results: dict[str, object]) -> dict[str, object]:
    risk = score(elf=results["elf"], strings=results["strings"], yara=results["yara"])
    return build_report(
        sample={"id": sample.id, "filename": sample.filename, "size": sample.size,
                "sha256": sample.sha256, "sha1": sample.sha1, "md5": sample.md5,
                "file_type": sample.file_type},
        elf=results["elf"],
        elf_error=results["elf_error"],
        strings=results["strings"],
        yara=results["yara"],
        risk=risk,
        generated_at=datetime.now(UTC).isoformat(),
    )


def _advance(session: Session, job: AnalysisJob, sample: Sample, nxt: AnalysisState) -> None:
    current = AnalysisState(job.state)
    validate_transition(current, nxt)
    now = datetime.now(UTC)
    session.add(StateTransition(job_id=job.id, from_state=job.state, to_state=nxt.value,
                                changed_at=now))
    job.state = nxt.value
    job.updated_at = now
    sample.analysis_status = nxt.value
    session.commit()


def _fail(session: Session, job: AnalysisJob | None, reason: str) -> AnalysisState:
    if job is None:
        return AnalysisState.FAILED
    current = AnalysisState(job.state)
    validate_transition(current, AnalysisState.FAILED)
    session.add(StateTransition(job_id=job.id, from_state=job.state,
                                to_state=AnalysisState.FAILED.value))
    job.state = AnalysisState.FAILED.value
    job.error = reason[:MAX_ERROR_CHARS]
    job.updated_at = datetime.now(UTC)
    session.commit()
    metrics.ANALYSIS_JOBS_TOTAL.labels(state="FAILED").inc()
    return AnalysisState.FAILED


def main() -> None:  # pragma: no cover - entry point, exercised by running the worker
    logging.basicConfig(level=logging.INFO)
    settings = Settings.from_env()
    port = int(os.environ.get("MALVAX_WORKER_METRICS_PORT", "9110"))
    prometheus_client.start_http_server(port)
    engine = make_engine(settings.database_url)
    session_factory = make_session_factory(engine)
    import redis

    queue = RedisQueue(redis.Redis.from_url(settings.redis_url))
    log.info("worker started; queue=%s", settings.redis_url)
    run_forever(session_factory, queue, settings)



if __name__ == "__main__":
    main()
