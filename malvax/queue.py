"""Job queue for background analysis (Phase 12).

The API only enqueues a job id. A worker (added in a later step) pops ids and runs the
pipeline. Redis is the production backend; the in-memory queue is for tests.
"""

from __future__ import annotations

from collections import deque
from typing import Protocol

from redis import exceptions as redis_exceptions

QUEUE_KEY = "malvax:analysis:jobs"


class JobQueue(Protocol):
    def enqueue(self, job_id: str) -> None: ...

    def dequeue(self, timeout_s: float) -> str | None: ...

    def ping(self) -> bool: ...


class InMemoryQueue:
    def __init__(self) -> None:
        self.items: deque[str] = deque()

    def enqueue(self, job_id: str) -> None:
        self.items.append(job_id)

    def dequeue(self, timeout_s: float) -> str | None:
        return self.items.popleft() if self.items else None

    def ping(self) -> bool:
        return True


class RedisQueue:
    def __init__(self, redis_client: object) -> None:
        self._redis = redis_client

    def enqueue(self, job_id: str) -> None:
        self._redis.rpush(QUEUE_KEY, job_id)  # type: ignore[attr-defined]

    def dequeue(self, timeout_s: float) -> str | None:
        try:
            item = self._redis.blpop(QUEUE_KEY, timeout=int(timeout_s))  # type: ignore[attr-defined]
        except redis_exceptions.TimeoutError:
            # The socket read timed out before BLPOP returned: treat it as an empty queue.
            return None
        if item is None:
            return None
        value = item[1]
        return value.decode() if isinstance(value, bytes) else str(value)

    def ping(self) -> bool:
        try:
            return bool(self._redis.ping())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - health check must not raise
            return False
