"""Analysis lifecycle state machine. Every transition is validated and recorded by the store."""

from __future__ import annotations

from enum import StrEnum


class AnalysisState(StrEnum):
    SUBMITTED = "SUBMITTED"
    QUEUED = "QUEUED"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    SANDBOX_PREPARATION = "SANDBOX_PREPARATION"
    EXECUTING = "EXECUTING"
    BEHAVIOR_COLLECTION = "BEHAVIOR_COLLECTION"
    ANALYSIS = "ANALYSIS"
    REPORT_GENERATION = "REPORT_GENERATION"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


TERMINAL_STATES: frozenset[AnalysisState] = frozenset(
    {AnalysisState.COMPLETED, AnalysisState.FAILED, AnalysisState.TIMEOUT, AnalysisState.CANCELLED}
)

_HAPPY_PATH: list[AnalysisState] = [
    AnalysisState.SUBMITTED,
    AnalysisState.QUEUED,
    AnalysisState.STATIC_ANALYSIS,
    AnalysisState.SANDBOX_PREPARATION,
    AnalysisState.EXECUTING,
    AnalysisState.BEHAVIOR_COLLECTION,
    AnalysisState.ANALYSIS,
    AnalysisState.REPORT_GENERATION,
    AnalysisState.COMPLETED,
]

ALLOWED_TRANSITIONS: dict[AnalysisState, frozenset[AnalysisState]] = {
    current: frozenset({nxt, AnalysisState.FAILED, AnalysisState.CANCELLED})
    for current, nxt in zip(_HAPPY_PATH, _HAPPY_PATH[1:], strict=False)
}
# Static-only path: used while the sandbox is not connected. Documented in docs/architecture.md.
ALLOWED_TRANSITIONS[AnalysisState.STATIC_ANALYSIS] = (
    ALLOWED_TRANSITIONS[AnalysisState.STATIC_ANALYSIS] | {AnalysisState.REPORT_GENERATION}
)
# Execution phases may also end in TIMEOUT.
ALLOWED_TRANSITIONS[AnalysisState.EXECUTING] = ALLOWED_TRANSITIONS[AnalysisState.EXECUTING] | {
    AnalysisState.TIMEOUT
}
ALLOWED_TRANSITIONS[AnalysisState.BEHAVIOR_COLLECTION] = (
    ALLOWED_TRANSITIONS[AnalysisState.BEHAVIOR_COLLECTION] | {AnalysisState.TIMEOUT}
)
for _terminal in TERMINAL_STATES:
    ALLOWED_TRANSITIONS[_terminal] = frozenset()


class InvalidTransitionError(ValueError):
    """Raised when a state change is not part of the lifecycle."""


def validate_transition(current: AnalysisState, nxt: AnalysisState) -> None:
    if nxt not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise InvalidTransitionError(f"illegal transition {current} -> {nxt}")
