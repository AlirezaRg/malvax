"""Dynamic telemetry -> behavior events, findings, and a risk contribution (Phase 4 integration).

Input is the telemetry document written by guest_collector. The module does not run anything.

Time handling: process events carry an observation time. Filesystem events and sockets are only
known at the end of the run, so they have no per-event time. Timing-based correlation rules are
therefore NOT applied to dynamic evidence; that would invent an order that was never observed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from malvax.correlation import BehaviorEvent, BehaviorType, Finding, build_timeline
from malvax.net_monitor import Connection
from malvax.risk import RiskReport, score

_FS_TYPES = {
    "CREATE": BehaviorType.FILE_CREATED,
    "MODIFY": BehaviorType.FILE_MODIFIED,
    "DELETE": BehaviorType.FILE_DELETED,
    "RENAME": BehaviorType.FILE_RENAMED,
}


def to_events(telemetry: dict[str, Any]) -> list[BehaviorEvent]:
    meta = telemetry["execution_metadata"]
    end_s = float(meta["finished_at"]) - float(meta["started_at"])
    events: list[BehaviorEvent] = []
    for p in telemetry["process_events"]:
        events.append(BehaviorEvent(
            event_id=f"proc-{p['pid']}", time_s=float(p["observed_at"]),
            type=BehaviorType.PROCESS_CREATED, pid=p["pid"], process=p["name"],
            succeeded=True,
            detail={"ppid": p["ppid"], "cmdline": p["cmdline"], "uid": p["uid"]},
        ))
    for i, f in enumerate(telemetry["filesystem_events"]):
        kind = _FS_TYPES.get(f["operation"])
        if kind is None:
            continue
        events.append(BehaviorEvent(
            event_id=f"fs-{i}", time_s=end_s, type=kind, pid=None, process=None,
            succeeded=True, detail={"path": f["path"], "size": f["size"], "sha256": f["sha256"]},
        ))
    for i, s in enumerate(telemetry["network_events"]):
        events.append(BehaviorEvent(
            event_id=f"net-{i}", time_s=end_s, type=BehaviorType.NETWORK_CONNECTION,
            pid=s["pid"], process=s["process"], succeeded=None,
            detail={"destination": s["destination"], "port": s["destination_port"],
                    "state": s["state"], "protocol": s["protocol"]},
        ))
    return events


def child_findings(telemetry: dict[str, Any]) -> list[Finding]:
    """A child is a process whose parent is also a process observed in this run."""
    observed = {p["pid"]: p for p in telemetry["process_events"]}
    findings: list[Finding] = []
    for pid, proc in observed.items():
        parent = proc["ppid"]
        if parent in observed:
            findings.append(Finding(
                rule="CHILD_PROCESS",
                title=f"Process {pid} ({proc['name']}) started by observed process {parent}",
                observed=(f"proc-{parent}", f"proc-{pid}"),
                inference="Parent and child were both observed during this run.",
            ))
    return findings


def connections(telemetry: dict[str, Any]) -> list[Connection]:
    return [
        Connection(
            protocol=s["protocol"], family=s["family"], source=s["source"],
            source_port=s["source_port"], destination=s["destination"],
            destination_port=s["destination_port"], state=s["state"], inode=s["inode"],
            pid=s["pid"], process=s["process"],
        )
        for s in telemetry["network_events"]
    ]


def dynamic_section(telemetry: dict[str, Any]) -> dict[str, Any]:
    """The `execution` block for a report, built only from observed telemetry."""
    meta = telemetry["execution_metadata"]
    events = to_events(telemetry)
    timeline = build_timeline(events)
    findings = child_findings(telemetry)
    risk: RiskReport = score(timeline=timeline, connections=connections(telemetry),
                             findings=findings)
    parents = {p["pid"]: p["ppid"] for p in telemetry["process_events"]}
    return {
        "execution_metadata": {
            "started_at": datetime.fromtimestamp(meta["started_at"], UTC).isoformat(),
            "finished_at": datetime.fromtimestamp(meta["finished_at"], UTC).isoformat(),
            "exit_code": meta["exit_code"],
            "timeout": meta["timeout"],
            "timeout_s": meta["timeout_s"],
            "poll_interval_s": meta["poll_interval_s"],
            "sockets_in_guest": meta.get("sockets_in_guest"),
            "sockets_attributed_to_sample": meta.get("sockets_attributed_to_sample"),
            "sample_stdout": meta["stdout_text"],
        },
        "process_tree": {"observed_pids": sorted(parents), "parent_of": parents},
        "filesystem_changes": telemetry["filesystem_events"],
        "network_activity": telemetry["network_events"],
        "syscalls": telemetry["syscall_events"],  # NOT_COLLECTED until strace is installed
        "behavioral_events": [
            {"id": e.event_id, "type": e.type.value, "pid": e.pid, "process": e.process,
             "detail": e.detail}
            for e in timeline
        ],
        "findings": [{"rule": f.rule, "title": f.title, "observed": list(f.observed),
                      "inference": f.inference} for f in findings],
        "risk": {
            "total": risk.total,
            "component_totals": risk.component_totals,
            "contributions": [
                {"component": c.component, "points": c.points, "reason": c.reason,
                 "evidence": list(c.evidence)}
                for c in risk.contributions
            ],
        },
    }
