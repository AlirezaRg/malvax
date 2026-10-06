"""Prometheus metrics (Phase 16).

Names follow the project specification. Counters only ever go up, so rates are computed in
Prometheus. The sandbox metrics exist already and stay at zero until the sandbox is connected:
a zero there means "no sandbox runs yet", not "no timeouts happened".
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

SAMPLES_TOTAL = Counter("malvax_samples_total", "Samples accepted by intake (new, not duplicates)")
ANALYSIS_JOBS_TOTAL = Counter(
    "malvax_analysis_jobs_total", "Analysis job state changes", ["state"]
)
ANALYSIS_DURATION_SECONDS = Histogram(
    "malvax_analysis_duration_seconds",
    "Wall time of one analysis run in the worker",
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300),
)
ANALYSIS_FAILURES_TOTAL = Counter("malvax_analysis_failures_total", "Analyses that ended FAILED")
FINDINGS_TOTAL = Counter("malvax_findings_total", "Risk contributions recorded as findings")
SANDBOX_TIMEOUTS_TOTAL = Counter(
    "malvax_sandbox_timeouts_total", "Sandbox runs stopped by the execution timeout"
)
WORKER_ACTIVE = Gauge("malvax_worker_active", "Jobs currently being processed by this worker")
