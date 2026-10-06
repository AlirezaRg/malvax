from redis import exceptions as redis_exceptions

from malvax.queue import RedisQueue


class _FakeRedis:
    def __init__(self, result=None, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple] = []

    def blpop(self, key, timeout):
        self.calls.append((key, timeout))
        if self.error is not None:
            raise self.error
        return self.result


def test_dequeue_returns_job_id_as_text() -> None:
    queue = RedisQueue(_FakeRedis(result=(b"malvax:analysis:jobs", b"job-1")))
    assert queue.dequeue(5.0) == "job-1"


def test_dequeue_empty_returns_none() -> None:
    assert RedisQueue(_FakeRedis(result=None)).dequeue(5.0) is None


def test_read_timeout_is_treated_as_empty_queue() -> None:
    fake = _FakeRedis(error=redis_exceptions.TimeoutError("Timeout reading from socket"))
    assert RedisQueue(fake).dequeue(5.0) is None


def test_enqueue_pushes_to_the_analysis_key() -> None:
    class _Pusher(_FakeRedis):
        def rpush(self, key, value):
            self.calls.append((key, value))

    fake = _Pusher()
    RedisQueue(fake).enqueue("job-9")
    assert fake.calls == [("malvax:analysis:jobs", "job-9")]
