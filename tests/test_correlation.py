from datetime import UTC, datetime

from malvax.correlation import (
    BehaviorEvent,
    BehaviorType,
    build_timeline,
    correlate,
    from_connection,
    from_fs,
    from_syscall,
    group_by_process,
    parse_time_of_day,
)
from malvax.fs_monitor import FsEvent, FsOperation
from malvax.net_monitor import Connection
from malvax.syscall_monitor import SyscallEvent


def _ev(eid: str, t: float, kind: BehaviorType, pid: int | None = 1,
        proc: str | None = "sample", ok: bool | None = True) -> BehaviorEvent:
    return BehaviorEvent(eid, t, kind, pid, proc, ok, {})


def test_time_of_day_parses_microseconds() -> None:
    assert parse_time_of_day("12:00:01.000200") == 12 * 3600 + 1 + 0.0002
    assert parse_time_of_day("00:00:05") == 5.0


def test_syscall_mapping_and_result_success() -> None:
    ev = SyscallEvent(4242, "12:00:01.000300", "connect", None, "10.0.0.5", 443,
                      "-1 EINPROGRESS", "raw")
    out = from_syscall(0, ev)
    assert out is not None
    assert out.type is BehaviorType.NETWORK_CONNECTION
    assert out.succeeded is False  # the leading -1 marks failure


def test_untimed_syscall_is_skipped() -> None:
    ev = SyscallEvent(None, None, "execve", "/x", None, None, "0", "raw")
    assert from_syscall(0, ev) is None


def test_unlisted_syscall_is_not_a_behavior() -> None:
    ev = SyscallEvent(None, "12:00:00", "read", None, None, None, "4", "raw")
    assert from_syscall(0, ev) is None


def test_fs_mapping_uses_iso_timestamp() -> None:
    fs = FsEvent("2026-01-01T00:00:02+00:00", FsOperation.CREATE, "out.txt", None, 3, "ab", None)
    out = from_fs(0, fs)
    assert out.type is BehaviorType.FILE_CREATED
    assert out.time_s == datetime(2026, 1, 1, 0, 0, 2, tzinfo=UTC).timestamp()


def test_timeline_is_sorted_by_time() -> None:
    events = [_ev("b", 2.0, BehaviorType.FILE_CREATED), _ev("a", 1.0, BehaviorType.FILE_DELETED)]
    assert [e.event_id for e in build_timeline(events)] == ["a", "b"]


def test_write_then_connect_within_window_is_found() -> None:
    timeline = build_timeline([
        _ev("w", 10.0, BehaviorType.FILE_CREATED),
        _ev("c", 12.0, BehaviorType.NETWORK_CONNECTION),
    ])
    (finding,) = [f for f in correlate(timeline) if f.rule == "WRITE_THEN_CONNECT"]
    assert finding.observed == ("w", "c")
    assert "not proof" in finding.inference


def test_write_then_connect_outside_window_is_ignored() -> None:
    timeline = [
        _ev("w", 10.0, BehaviorType.FILE_CREATED),
        _ev("c", 100.0, BehaviorType.NETWORK_CONNECTION),
    ]
    assert not [f for f in correlate(timeline) if f.rule == "WRITE_THEN_CONNECT"]


def test_child_process_needs_parent_map() -> None:
    timeline = [
        _ev("p", 1.0, BehaviorType.PROCESS_CREATED, pid=10),
        _ev("k", 2.0, BehaviorType.PROCESS_CREATED, pid=11),
    ]
    assert not [f for f in correlate(timeline) if f.rule == "CHILD_PROCESS"]
    (finding,) = [f for f in correlate(timeline, {11: 10}) if f.rule == "CHILD_PROCESS"]
    assert finding.observed == ("p", "k")


def test_privilege_attempt_counts_failures() -> None:
    timeline = [
        _ev("s1", 1.0, BehaviorType.PRIVILEGE_CHANGE, ok=False),
        _ev("s2", 2.0, BehaviorType.PRIVILEGE_CHANGE, ok=True),
    ]
    (finding,) = [f for f in correlate(timeline) if f.rule == "PRIVILEGE_ATTEMPT"]
    assert "1 failed" in finding.title


def test_mass_delete_threshold() -> None:
    few = [_ev(f"d{i}", float(i), BehaviorType.FILE_DELETED) for i in range(4)]
    many = [_ev(f"d{i}", float(i), BehaviorType.FILE_DELETED) for i in range(5)]
    assert not [f for f in correlate(few) if f.rule == "MASS_DELETE"]
    assert [f for f in correlate(many) if f.rule == "MASS_DELETE"]


def test_connection_event_keeps_destination() -> None:
    conn = Connection("tcp", "ipv4", "127.0.0.1", 5000, "10.0.0.5", 443, "ESTABLISHED",
                      1, pid=7, process="sample")
    out = from_connection(0, conn, 3.0)
    assert out.detail["destination"] == "10.0.0.5" and out.pid == 7


def test_group_by_process() -> None:
    timeline = [
        _ev("a", 1.0, BehaviorType.FILE_CREATED, proc="x"),
        _ev("b", 2.0, BehaviorType.FILE_CREATED, proc="y"),
        _ev("c", 3.0, BehaviorType.FILE_DELETED, proc="x"),
    ]
    groups = group_by_process(timeline)
    assert [e.event_id for e in groups["x"]] == ["a", "c"]
