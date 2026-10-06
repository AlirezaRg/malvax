from malvax.correlation import BehaviorType
from malvax.dynamic import child_findings, dynamic_section, to_events


def _telemetry(**overrides):
    base = {
        "sample_sha256": "ab" * 32,
        "process_events": [
            {"pid": 100, "ppid": 1, "name": "sh", "cmdline": "sh sample", "uid": 1001, "gid": 1001,
             "start_ticks": 1, "observed_at": 0.2},
            {"pid": 101, "ppid": 100, "name": "sleep", "cmdline": "sleep 2", "uid": 1001,
             "gid": 1001, "start_ticks": 2, "observed_at": 0.4},
        ],
        "filesystem_events": [
            {"operation": "CREATE", "path": "out.txt", "old_path": None, "size": 3, "sha256": "x"},
        ],
        "network_events": [
            {"protocol": "tcp", "family": "ipv4", "source": "127.0.0.1", "source_port": 40000,
             "destination": "10.0.0.5", "destination_port": 443, "state": "ESTABLISHED",
             "inode": 9, "pid": 101, "process": "sleep"},
        ],
        "syscall_events": "NOT_COLLECTED",
        "execution_metadata": {
            "started_at": 1000.0, "finished_at": 1003.0, "exit_code": 0, "timeout": False,
            "timeout_s": 60, "poll_interval_s": 0.2, "stdout_text": "ok\n",
            "sockets_in_guest": 27, "sockets_attributed_to_sample": 1,
        },
    }
    base.update(overrides)
    return base


def test_events_have_expected_types() -> None:
    types = [e.type for e in to_events(_telemetry())]
    assert types.count(BehaviorType.PROCESS_CREATED) == 2
    assert BehaviorType.FILE_CREATED in types
    assert BehaviorType.NETWORK_CONNECTION in types


def test_child_finding_needs_both_processes_observed() -> None:
    findings = child_findings(_telemetry())
    assert [f.rule for f in findings] == ["CHILD_PROCESS"]
    assert findings[0].observed == ("proc-100", "proc-101")


def test_orphan_process_is_not_called_a_child() -> None:
    t = _telemetry()
    t["process_events"] = [t["process_events"][1]]  # parent 100 was not observed
    assert child_findings(t) == []


def test_dynamic_section_risk_has_evidence_for_every_contribution() -> None:
    section = dynamic_section(_telemetry())
    assert section["risk"]["total"] > 0
    for c in section["risk"]["contributions"]:
        assert c["evidence"], f"no evidence for {c['reason']}"


def test_unobserved_syscalls_are_marked_not_collected() -> None:
    assert dynamic_section(_telemetry())["syscalls"] == "NOT_COLLECTED"


def test_sample_output_is_carried_into_the_section() -> None:
    assert dynamic_section(_telemetry())["execution_metadata"]["sample_stdout"] == "ok\n"


def test_dynamic_section_never_applies_the_timing_rule() -> None:
    # Filesystem and socket evidence has no per-event time, so WRITE_THEN_CONNECT must not fire.
    findings = dynamic_section(_telemetry())["findings"]
    assert not any(f["rule"] == "WRITE_THEN_CONNECT" for f in findings)
