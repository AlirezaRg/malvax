"""System-call monitoring with strace (Phase 8).

Two parts:
1. build_strace_command: an argv list for strace that traces only security-relevant calls.
   It is a list, never a shell string, so sample-controlled names cannot inject arguments.
2. parse_strace_output: turns strace text into SyscallEvent records.

This module does not run strace on samples. Execution happens inside the sandbox VM (Phase 4).

Limits:
- Lines marked "<unfinished ...>" or "resumed>" are not joined into one event. They are counted
  in ParseResult.unmatched so the report can say how much data was lost.
- strace slows the traced program down. Timing numbers from traced runs are not comparable to
  untraced runs and must be reported that way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SECURITY_SYSCALLS: tuple[str, ...] = (
    "execve",
    "openat",
    "connect",
    "socket",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "chmod",
    "fchmodat",
    "setuid",
    "setgid",
    "setresuid",
    "setresgid",
)

_LINE = re.compile(
    r"^(?:\[pid\s+(?P<bracket_pid>\d+)\]\s+|(?P<pid>\d+)\s+)?"
    r"(?:(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+)?"
    r"(?P<name>[a-z_0-9]+)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$"
)
_QUOTED_PATH = re.compile(r'"((?:[^"\\]|\\.)*)"')
_SOCKADDR = re.compile(r'sin_port=htons\((\d+)\).*?inet_addr\("([0-9.]+)"\)')


class StraceError(ValueError):
    """Raised when the trace path or the sample path is not usable."""


@dataclass(frozen=True, slots=True)
class SyscallEvent:
    pid: int | None
    timestamp: str | None
    name: str
    path: str | None
    destination: str | None
    port: int | None
    result: str
    raw: str


@dataclass(slots=True)
class ParseResult:
    events: list[SyscallEvent] = field(default_factory=list)
    unmatched: int = 0


def build_strace_command(
    sample: str,
    output: str,
    strace_binary: str = "strace",
    syscalls: tuple[str, ...] = SECURITY_SYSCALLS,
) -> list[str]:
    """Return argv for strace. Follows children (-f), adds timestamps (-tt), writes to a file.

    Paths are plain strings in the sandbox's POSIX form. The check below uses that form, not
    the host's, so the same command builds correctly on Windows and Linux controllers.
    """
    if not sample.startswith("/") or "\x00" in sample:
        raise StraceError("sample path must be an absolute POSIX path inside the sandbox")
    return [
        strace_binary,
        "-f",
        "-tt",
        "-e",
        "trace=" + ",".join(syscalls),
        "-o",
        output,
        "--",
        sample,
    ]


def parse_strace_output(text: str) -> ParseResult:
    result = ParseResult()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "<unfinished" in line or "resumed>" in line:
            result.unmatched += 1
            continue
        match = _LINE.match(line)
        if match is None:
            result.unmatched += 1
            continue
        name = match["name"]
        args = match["args"]
        pid_text = match["bracket_pid"] or match["pid"]
        path, destination, port = _extract_target(name, args)
        result.events.append(
            SyscallEvent(
                pid=int(pid_text) if pid_text else None,
                timestamp=match["time"],
                name=name,
                path=path,
                destination=destination,
                port=port,
                result=match["result"].strip(),
                raw=line,
            )
        )
    return result


def _extract_target(name: str, args: str) -> tuple[str | None, str | None, int | None]:
    if name == "connect":
        sock = _SOCKADDR.search(args)
        if sock:
            return None, sock.group(2), int(sock.group(1))
        return None, None, None
    if name in {"execve", "openat", "unlink", "unlinkat", "rename", "renameat", "renameat2",
                "chmod", "fchmodat"}:
        quoted = _QUOTED_PATH.search(args)
        return (quoted.group(1) if quoted else None), None, None
    return None, None, None
