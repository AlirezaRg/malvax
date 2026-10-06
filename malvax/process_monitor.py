"""Process monitoring from /proc (Phase 5).

Reads a snapshot of processes from a proc filesystem root and builds a parent/child tree.
Only reads files; never sends signals and never executes anything.

Limits: /proc does not record exit codes or end times for processes that already exited.
Those fields stay None until an event-based collector (ptrace/strace/audit, Phase 8) fills them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

PROC_ROOT = Path("/proc")
# Field index of starttime (clock ticks since boot) in /proc/<pid>/stat, counted after the
# closing parenthesis of the command name.
_STAT_STARTTIME_INDEX = 19
_STAT_PPID_INDEX = 1


@dataclass(frozen=True, slots=True)
class ProcessRecord:
    pid: int
    ppid: int
    name: str
    cmdline: str
    uid: int | None
    gid: int | None
    start_ticks: int | None


@dataclass(slots=True)
class ProcessNode:
    record: ProcessRecord
    children: list[ProcessNode] = field(default_factory=list)


def read_process(pid_dir: Path) -> ProcessRecord | None:
    """Parse one /proc/<pid> directory. Returns None if the process vanished mid-read."""
    try:
        pid = int(pid_dir.name)
        stat = (pid_dir / "stat").read_text(encoding="utf-8", errors="replace")
        status = (pid_dir / "status").read_text(encoding="utf-8", errors="replace")
        raw_cmd = (pid_dir / "cmdline").read_bytes()
    except (ValueError, FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    name, rest = _split_stat(stat)
    fields = rest.split()
    if len(fields) <= _STAT_STARTTIME_INDEX:
        return None
    return ProcessRecord(
        pid=pid,
        ppid=int(fields[_STAT_PPID_INDEX]),
        name=name,
        cmdline=_decode_cmdline(raw_cmd, fallback=name),
        uid=_status_id(status, "Uid"),
        gid=_status_id(status, "Gid"),
        start_ticks=int(fields[_STAT_STARTTIME_INDEX]),
    )


def snapshot(proc_root: Path = PROC_ROOT) -> list[ProcessRecord]:
    records: list[ProcessRecord] = []
    for entry in proc_root.iterdir():
        if entry.name.isdigit() and entry.is_dir():
            record = read_process(entry)
            if record is not None:
                records.append(record)
    return sorted(records, key=lambda r: r.pid)


def build_tree(records: list[ProcessRecord]) -> list[ProcessNode]:
    """Return root nodes. A process is a root if its parent is not in the snapshot."""
    nodes = {r.pid: ProcessNode(record=r) for r in records}
    roots: list[ProcessNode] = []
    for node in nodes.values():
        parent = nodes.get(node.record.ppid)
        if parent is None or parent is node:
            roots.append(node)
        else:
            parent.children.append(node)
    for node in nodes.values():
        node.children.sort(key=lambda n: n.record.pid)
    return sorted(roots, key=lambda n: n.record.pid)


def render_tree(roots: list[ProcessNode]) -> str:
    lines: list[str] = []

    def walk(node: ProcessNode, prefix: str, last: bool, top: bool) -> None:
        label = f"{node.record.name} (pid {node.record.pid})"
        if top:
            lines.append(label)
            child_prefix = ""
        else:
            lines.append(f"{prefix}{'└── ' if last else '├── '}{label}")
            child_prefix = prefix + ("    " if last else "│   ")
        for index, child in enumerate(node.children):
            walk(child, child_prefix, index == len(node.children) - 1, top=False)

    for root in roots:
        walk(root, "", True, top=True)
    return "\n".join(lines)


def _split_stat(stat: str) -> tuple[str, str]:
    # The command name is in parentheses and may itself contain spaces or parentheses.
    start = stat.index("(")
    end = stat.rindex(")")
    return stat[start + 1 : end], stat[end + 2 :]


def _decode_cmdline(raw: bytes, fallback: str) -> str:
    parts = [p.decode("utf-8", errors="replace") for p in raw.split(b"\x00") if p]
    return " ".join(parts) if parts else f"[{fallback}]"


def _status_id(status: str, key: str) -> int | None:
    for line in status.splitlines():
        if line.startswith(f"{key}:"):
            values = line.split()[1:]
            return int(values[0]) if values else None
    return None
