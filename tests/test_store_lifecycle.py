from pathlib import Path

import pytest

from malvax.intake import intake_sample
from malvax.lifecycle import AnalysisState, InvalidTransitionError, validate_transition
from malvax.store import SampleStore


@pytest.fixture
def store(tmp_path: Path) -> SampleStore:
    s = SampleStore(tmp_path / "malvax.db")
    yield s
    s.close()


def _sample(tmp_path: Path, content: bytes = b"\x7fELF" + b"\x02" * 32):
    f = tmp_path / "sample.elf"
    f.write_bytes(content)
    return intake_sample(f)


def test_add_sample_records_submitted_transition(tmp_path: Path, store: SampleStore) -> None:
    stored = store.add_sample(_sample(tmp_path))
    assert stored.analysis_status is AnalysisState.SUBMITTED
    assert store.transitions(stored.id) == [(None, "SUBMITTED")]


def test_duplicate_sha256_returns_existing_row(tmp_path: Path, store: SampleStore) -> None:
    first = store.add_sample(_sample(tmp_path))
    second = store.add_sample(_sample(tmp_path))
    assert first.id == second.id


def test_happy_path_transitions_are_recorded(tmp_path: Path, store: SampleStore) -> None:
    sample = store.add_sample(_sample(tmp_path))
    path = [
        AnalysisState.QUEUED,
        AnalysisState.STATIC_ANALYSIS,
        AnalysisState.SANDBOX_PREPARATION,
        AnalysisState.EXECUTING,
        AnalysisState.BEHAVIOR_COLLECTION,
        AnalysisState.ANALYSIS,
        AnalysisState.REPORT_GENERATION,
        AnalysisState.COMPLETED,
    ]
    for state in path:
        store.transition(sample.id, state)
    assert store.get(sample.id).analysis_status is AnalysisState.COMPLETED  # type: ignore[union-attr]
    assert len(store.transitions(sample.id)) == 1 + len(path)


def test_cannot_skip_states(tmp_path: Path, store: SampleStore) -> None:
    sample = store.add_sample(_sample(tmp_path))
    with pytest.raises(InvalidTransitionError):
        store.transition(sample.id, AnalysisState.EXECUTING)


def test_terminal_states_are_final() -> None:
    with pytest.raises(InvalidTransitionError):
        validate_transition(AnalysisState.COMPLETED, AnalysisState.QUEUED)
    with pytest.raises(InvalidTransitionError):
        validate_transition(AnalysisState.FAILED, AnalysisState.QUEUED)


def test_timeout_only_from_execution_phases() -> None:
    validate_transition(AnalysisState.EXECUTING, AnalysisState.TIMEOUT)
    validate_transition(AnalysisState.BEHAVIOR_COLLECTION, AnalysisState.TIMEOUT)
    with pytest.raises(InvalidTransitionError):
        validate_transition(AnalysisState.STATIC_ANALYSIS, AnalysisState.TIMEOUT)
