"""Network connection monitoring from /proc/net (Phase 7).

Reads TCP and UDP socket tables, decodes their addresses, and maps each socket inode to the
process that owns it through /proc/<pid>/fd. Read-only: no sockets are opened and no packets
are sent.

Limits:
- The owning process is found by scanning fd links. Short-lived sockets can close before the
  scan, and processes owned by other users may not be readable without privileges.
- Only connections that exist at snapshot time are reported. Connections opened and closed
  between two snapshots are missed. Event-level capture needs eBPF or audit (Phase 8).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

PROC_ROOT = Path("/proc")

_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}
_UDP_STATE_NAME = "UNCONN"  # UDP sockets have no state machine in /proc/net/udp


class NetworkMode(StrEnum):
    """OFFLINE is the default: no route out of the sandbox."""

    OFFLINE = "OFFLINE"
    ISOLATED = "ISOLATED"
    CONTROLLED = "CONTROLLED"


def parse_network_mode(value: str | None) -> NetworkMode:
    """Unknown or missing values fall back to OFFLINE, never to a more open mode."""
    try:
        return NetworkMode(value.upper()) if value else NetworkMode.OFFLINE
    except ValueError:
        return NetworkMode.OFFLINE


@dataclass(frozen=True, slots=True)
class Connection:
    protocol: str  # "tcp" or "udp"
    family: str  # "ipv4" or "ipv6"
    source: str
    source_port: int
    destination: str
    destination_port: int
    state: str
    inode: int
    pid: int | None = None
    process: str | None = None


def decode_address(hex_addr: str, family: str) -> tuple[str, int]:
    """Decode the kernel's `ADDR:PORT` hex form. Addresses are stored in host byte order."""
    addr_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    if family == "ipv4":
        raw = struct.pack("<I", int(addr_hex, 16))
        return socket.inet_ntop(socket.AF_INET, raw), port
    words = [addr_hex[i : i + 8] for i in range(0, 32, 8)]
    raw = b"".join(struct.pack("<I", int(w, 16)) for w in words)
    return socket.inet_ntop(socket.AF_INET6, raw), port


def parse_table(text: str, protocol: str, family: str) -> list[Connection]:
    connections: list[Connection] = []
    for line in text.splitlines()[1:]:  # first line is the header
        fields = line.split()
        if len(fields) < 10:
            continue
        src, src_port = decode_address(fields[1], family)
        dst, dst_port = decode_address(fields[2], family)
        state = _TCP_STATES.get(fields[3], fields[3]) if protocol == "tcp" else _UDP_STATE_NAME
        connections.append(
            Connection(
                protocol=protocol,
                family=family,
                source=src,
                source_port=src_port,
                destination=dst,
                destination_port=dst_port,
                state=state,
                inode=int(fields[9]),
            )
        )
    return connections


def read_connections(proc_root: Path = PROC_ROOT) -> list[Connection]:
    net = proc_root / "net"
    tables = [
        ("tcp", "ipv4", "tcp"), ("tcp6", "ipv6", "tcp"),
        ("udp", "ipv4", "udp"), ("udp6", "ipv6", "udp"),
    ]
    found: list[Connection] = []
    for filename, family, protocol in tables:
        path = net / filename
        if path.exists():
            found.extend(parse_table(path.read_text(errors="replace"), protocol, family))
    return _attach_owners(found, proc_root)


def _attach_owners(connections: list[Connection], proc_root: Path) -> list[Connection]:
    owners = _socket_owners(proc_root)
    attached: list[Connection] = []
    for conn in connections:
        pid, name = owners.get(conn.inode, (None, None))
        attached.append(
            Connection(
                protocol=conn.protocol, family=conn.family, source=conn.source,
                source_port=conn.source_port, destination=conn.destination,
                destination_port=conn.destination_port, state=conn.state,
                inode=conn.inode, pid=pid, process=name,
            )
        )
    return attached


def _socket_owners(proc_root: Path) -> dict[int, tuple[int, str]]:
    owners: dict[int, tuple[int, str]] = {}
    for pid_dir in proc_root.iterdir():
        if not pid_dir.name.isdigit():
            continue
        fd_dir = pid_dir / "fd"
        try:
            name = (pid_dir / "comm").read_text().strip()
            links = list(fd_dir.iterdir())
        except (FileNotFoundError, PermissionError, ProcessLookupError, NotADirectoryError):
            continue
        for link in links:
            try:
                target = link.readlink().as_posix()
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                owners.setdefault(int(target[8:-1]), (int(pid_dir.name), name))
    return owners
