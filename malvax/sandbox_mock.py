"""In-memory sandbox provider for unit tests. It runs nothing: it records what the lifecycle asked
for and returns scripted results. Never used for real analysis."""

from __future__ import annotations

from pathlib import Path

from malvax.sandbox import RunResult


class MockSandboxProvider:
    name = "mock"

    def __init__(self, run_result: RunResult | None = None, fail_at: str | None = None) -> None:
        self.calls: list[tuple] = []
        self._result = run_result or RunResult(exit_code=0, timed_out=False, stdout=b"", stderr=b"")
        self._fail_at = fail_at

    def _maybe_fail(self, step: str) -> None:
        if self._fail_at == step:
            raise RuntimeError(f"scripted failure at {step}")

    def revert(self, snapshot: str) -> None:
        self.calls.append(("revert", snapshot))
        self._maybe_fail("revert")

    def start(self) -> None:
        self.calls.append(("start",))
        self._maybe_fail("start")

    def wait_ready(self, timeout_s: int) -> None:
        self.calls.append(("wait_ready", timeout_s))
        self._maybe_fail("wait_ready")

    def copy_in(self, local: Path, remote: str) -> None:
        self.calls.append(("copy_in", local.name, remote))
        self._maybe_fail("copy_in")

    def run(self, argv: list[str], timeout_s: int) -> RunResult:
        self.calls.append(("run", tuple(argv), timeout_s))
        self._maybe_fail("run")
        return self._result

    def copy_out(self, remote: str, local: Path) -> None:
        self.calls.append(("copy_out", remote))

    def stop(self) -> None:
        self.calls.append(("stop",))
        self._maybe_fail("stop")
