"""Telemetry collector that runs INSIDE the analysis VM (guest side).

It starts the sample under resource limits and timeout, watches for process children, and compares
filesystem and socket state before and after. It writes one JSON document. It depends only on the
Python standard library and on fs_monitor, process_monitor and net_monitor, which have no third
party imports, so the controller can copy those four files into the guest.

Honest limits:
- Process polling runs every POLL_S seconds. A child that starts and exits between two polls is
  missed. This is reported in the telemetry as "poll_interval_s".
- Filesystem visibility is the snapshot diff of watch_dir only, not the whole guest.
- Syscalls are not collected here. The field is present and marked NOT_COLLECTED.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from malvax.fs_monitor import diff, take_snapshot
from malvax.net_monitor import read_connections
from malvax.process_monitor import snapshot as proc_snapshot

POLL_S = 0.2
MAX_TEXT = 64 * 1024  # sample output kept in telemetry; larger output is truncated
PROC_ROOT = Path("/proc")


def _ancestors_of(pid: int, parents: dict[int, int]) -> set[int]:
    seen: set[int] = set()
    current = pid
    while current in parents and current not in seen:
        seen.add(current)
        current = parents[current]
    return seen


def collect(run_argv: list[str], watch_dir: Path, timeout_s: int, sha256: str,
            poll_s: float = POLL_S, proc_root: Path = PROC_ROOT) -> dict[str, Any]:
    """Run run_argv, observe, and return the telemetry document (a plain dict)."""
    fs_before = take_snapshot(watch_dir)
    known = {r.pid for r in proc_snapshot(proc_root)}
    started_wall = time.time()
    started = time.monotonic()

    proc = subprocess.Popen(run_argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    process_events: list[dict[str, Any]] = []
    parents: dict[int, int] = {}
    seen_sockets: dict[tuple, Any] = {}  # sample-owned sockets, observed while they exist
    timed_out = False

    while proc.poll() is None:
        if time.monotonic() - started > timeout_s:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            break
        for rec in proc_snapshot(proc_root):
            if rec.pid in known:
                continue
            known.add(rec.pid)
            parents[rec.pid] = rec.ppid
            if rec.pid == proc.pid or proc.pid in _ancestors_of(rec.pid, parents):
                process_events.append({
                    "pid": rec.pid, "ppid": rec.ppid, "name": rec.name,
                    "cmdline": rec.cmdline, "uid": rec.uid, "gid": rec.gid,
                    "start_ticks": rec.start_ticks,
                    "observed_at": round(time.time() - started_wall, 3),
                })
        # A socket can exist only while the sample runs (a listener closes before exit), so
        # sockets are observed during the run, not only after it.
        live_pids = {e["pid"] for e in process_events} | {proc.pid}
        for conn in read_connections(proc_root):
            if conn.pid in live_pids:
                key = (conn.protocol, conn.source, conn.source_port, conn.destination,
                       conn.destination_port, conn.inode)
                seen_sockets.setdefault(key, conn)
        time.sleep(poll_s)

    stdout, stderr = proc.communicate(timeout=10)
    finished_wall = time.time()

    fs_after = take_snapshot(watch_dir)
    fs_events = [
        {"operation": e.operation.value, "path": e.path, "old_path": e.old_path,
         "size": e.size, "sha256": e.sha256}
        for e in diff(fs_before, fs_after, timestamp=None)
    ]
    # Only sockets owned by the sample's own processes are attributed to it. Everything else in
    # the guest is counted but not reported, so system sockets are not mistaken for sample activity.
    sample_pids = {e["pid"] for e in process_events} | {proc.pid}
    all_sockets = read_connections(proc_root)
    for conn in all_sockets:
        if conn.pid in sample_pids:
            key = (conn.protocol, conn.source, conn.source_port, conn.destination,
                   conn.destination_port, conn.inode)
            seen_sockets.setdefault(key, conn)
    sockets = [asdict(c) for c in seen_sockets.values()]

    return {
        "sample_sha256": sha256,
        "process_events": process_events,
        "filesystem_events": fs_events,
        "network_events": sockets,
        "syscall_events": "NOT_COLLECTED",
        "execution_metadata": {
            "started_at": started_wall,
            "finished_at": finished_wall,
            "exit_code": proc.returncode,
            "timeout": timed_out,
            "timeout_s": timeout_s,
            "poll_interval_s": poll_s,
            "watch_dir": str(watch_dir),
            "sockets_in_guest": len(all_sockets),
            "sockets_attributed_to_sample": len(sockets),
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "stdout_text": stdout[:MAX_TEXT].decode("utf-8", errors="replace"),
            "stderr_text": stderr[:MAX_TEXT].decode("utf-8", errors="replace"),
        },
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="guest-side sample telemetry collector")
    parser.add_argument("--sample", required=True, help="path of the sample inside the guest")
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--watch", required=True, help="directory to diff before and after")
    parser.add_argument("--out", required=True, help="where to write the telemetry JSON")
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args(argv)

    from malvax.sandbox import ExecutionLimits, guest_command

    run_argv = guest_command(ExecutionLimits(timeout_s=args.timeout), args.sample)
    telemetry = collect(run_argv, Path(args.watch), args.timeout, args.sha256)
    Path(args.out).write_text(json.dumps(telemetry, indent=2), encoding="utf-8")
    meta = telemetry["execution_metadata"]
    summary = {"written": args.out, "exit_code": meta["exit_code"], "timeout": meta["timeout"]}
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
