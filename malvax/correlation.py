"""Behavior normalization and correlation (Phase 9).

Raw events from the collectors become BehaviorEvent records on one timeline. Rules then look
for simple, documented patterns across those events. Every Finding lists the event ids it is
built from, so each conclusion can be traced back to observed data.

Separation of concepts:
- Observed: an event that a collector recorded (for example, connect() returned 0).
- Inference: a finding derived from observed events by a rule. The rule text is part of the
  finding, so a reader can judge it.

This module does not compute a risk score. That is Phase 10.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from malvax.fs_monitor import FsEvent, FsOperation
from malvax.net_monitor import Connection
from malvax.syscall_monitor import SyscallEvent

_TIME_OF_DAY = re.compile(r"^(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$")
PRIVILEGE_CALLS = frozenset({"setuid", "setgid", "setresuid", "setresgid"})
DELETE_CALLS = frozenset({"unlink", "unlinkat"})
MASS_DELETE_THRESHOLD = 5
WRITE_TO_CONNECT_WINDOW_S = 5.0


class BehaviorType(StrEnum):
    PROCESS_CREATED = "PROCESS_CREATED"
    CHILD_PROCESS_CREATED = "CHILD_PROCESS_CREATED"
    FILE_CREATED = "FILE_CREATED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_DELETED = "FILE_DELETED"
    FILE_RENAMED = "FILE_RENAMED"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"


@dataclass(frozen=True, slots=True)
class BehaviorEvent:
    event_id: str
    time_s: float
    type: BehaviorType
    pid: int | None
    process: str | None
    succeeded: bool | None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    title: str
    observed: tuple[str, ...]  # event ids the finding is built from
    inference: str  # what the rule concludes, stated as an inference, not a fact


def parse_time_of_day(text: str) -> float:
    """Convert strace's HH:MM:SS.micro into seconds since midnight."""
    match = _TIME_OF_DAY.match(text)
    if match is None:
        raise ValueError(f"not a time of day: {text!r}")
    hours, minutes, seconds, fraction = match.groups()
    frac = float(f"0.{fraction}") if fraction else 0.0
    return int(hours) * 3600 + int(minutes) * 60 + int(seconds) + frac


def from_syscall(index: int, ev: SyscallEvent) -> BehaviorEvent | None:
    if ev.timestamp is None:
        return None
    time_s = parse_time_of_day(ev.timestamp)
    eid = f"sys-{index}"
    ok = ev.result.split()[0] != "-1" if ev.result else None
    if ev.name == "execve":
        kind = BehaviorType.PROCESS_CREATED
    elif ev.name == "connect":
        kind = BehaviorType.NETWORK_CONNECTION
    elif ev.name in PRIVILEGE_CALLS:
        kind = BehaviorType.PRIVILEGE_CHANGE
    elif ev.name in DELETE_CALLS:
        kind = BehaviorType.FILE_DELETED
    elif ev.name in {"rename", "renameat", "renameat2"}:
        kind = BehaviorType.FILE_RENAMED
    else:
        return None
    detail = {"syscall": ev.name, "path": ev.path, "destination": ev.destination,
              "port": ev.port, "result": ev.result}
    return BehaviorEvent(eid, time_s, kind, ev.pid, None, ok, detail)


def from_fs(index: int, ev: FsEvent) -> BehaviorEvent:
    time_s = datetime.fromisoformat(ev.timestamp).timestamp()
    kind = {
        FsOperation.CREATE: BehaviorType.FILE_CREATED,
        FsOperation.MODIFY: BehaviorType.FILE_MODIFIED,
        FsOperation.DELETE: BehaviorType.FILE_DELETED,
        FsOperation.RENAME: BehaviorType.FILE_RENAMED,
    }[ev.operation]
    detail = {"path": ev.path, "old_path": ev.old_path, "size": ev.size, "sha256": ev.sha256}
    return BehaviorEvent(f"fs-{index}", time_s, kind, None, ev.process, True, detail)


def from_connection(index: int, conn: Connection, time_s: float) -> BehaviorEvent:
    detail = {"protocol": conn.protocol, "destination": conn.destination,
              "port": conn.destination_port, "state": conn.state}
    return BehaviorEvent(f"net-{index}", time_s, BehaviorType.NETWORK_CONNECTION,
                         conn.pid, conn.process, None, detail)


def build_timeline(events: list[BehaviorEvent]) -> list[BehaviorEvent]:
    return sorted(events, key=lambda e: (e.time_s, e.event_id))


def correlate(
    timeline: list[BehaviorEvent],
    parent_of: dict[int, int] | None = None,
) -> list[Finding]:
    """Run every rule. parent_of maps child pid to parent pid, from the process tree (Phase 5).

    Without parent_of, no child-process finding is made: the parent link is not guessed.
    """
    findings: list[Finding] = []
    findings.extend(_write_then_connect(timeline))
    findings.extend(_child_processes(timeline, parent_of or {}))
    findings.extend(_privilege_attempts(timeline))
    findings.extend(_mass_delete(timeline))
    return findings


def _write_then_connect(timeline: list[BehaviorEvent]) -> list[Finding]:
    writes = [e for e in timeline if e.type in {BehaviorType.FILE_CREATED,
                                                 BehaviorType.FILE_MODIFIED}]
    found: list[Finding] = []
    for write in writes:
        for conn in timeline:
            if conn.type is not BehaviorType.NETWORK_CONNECTION:
                continue
            gap = conn.time_s - write.time_s
            if 0 <= gap <= WRITE_TO_CONNECT_WINDOW_S:
                found.append(Finding(
                    rule="WRITE_THEN_CONNECT",
                    title="File written shortly before a network connection",
                    observed=(write.event_id, conn.event_id),
                    inference=(f"A file write was followed by a connection within "
                               f"{WRITE_TO_CONNECT_WINDOW_S:g}s. This is a timing relationship, "
                               "not proof that the file caused the connection."),
                ))
    return found


def _child_processes(
    timeline: list[BehaviorEvent], parent_of: dict[int, int]
) -> list[Finding]:
    """A process start is a child start when its parent pid is itself a traced process."""
    traced = {e.pid: e for e in timeline if e.pid is not None and
              e.type is BehaviorType.PROCESS_CREATED}
    found: list[Finding] = []
    for pid, event in traced.items():
        parent_pid = parent_of.get(pid)
        if parent_pid is None or parent_pid not in traced:
            continue
        parent_event = traced[parent_pid]
        found.append(Finding(
            rule="CHILD_PROCESS",
            title=f"Process {pid} was started by traced process {parent_pid}",
            observed=(parent_event.event_id, event.event_id),
            inference="The parent link comes from the process tree snapshot. The child started "
                      "inside the same traced run.",
        ))
    return found


def _privilege_attempts(timeline: list[BehaviorEvent]) -> list[Finding]:
    attempts = [e for e in timeline if e.type is BehaviorType.PRIVILEGE_CHANGE]
    if not attempts:
        return []
    ids = tuple(e.event_id for e in attempts)
    failed = sum(1 for e in attempts if e.succeeded is False)
    return [Finding(
        rule="PRIVILEGE_ATTEMPT",
        title=f"{len(attempts)} privilege change call(s), {failed} failed",
        observed=ids,
        inference="The sample requested a UID/GID change. A failed request means the kernel "
                  "refused it, which is not the same as the sample being harmless.",
    )]


def _mass_delete(timeline: list[BehaviorEvent]) -> list[Finding]:
    deletes = [e for e in timeline if e.type is BehaviorType.FILE_DELETED]
    if len(deletes) < MASS_DELETE_THRESHOLD:
        return []
    return [Finding(
        rule="MASS_DELETE",
        title=f"{len(deletes)} file deletions in one run",
        observed=tuple(e.event_id for e in deletes),
        inference=f"At least {MASS_DELETE_THRESHOLD} deletions were recorded. A cleanup "
                  "routine can produce the same pattern, so this is only an indicator.",
    )]


def group_by_process(timeline: list[BehaviorEvent]) -> dict[str, list[BehaviorEvent]]:
    keyed = sorted(timeline, key=lambda e: (e.process or "", e.time_s))
    return {k: list(v) for k, v in itertools.groupby(keyed, key=lambda e: e.process or "?")}
