import sys
from pathlib import Path

import pytest

from malvax.net_monitor import (
    NetworkMode,
    decode_address,
    parse_network_mode,
    parse_table,
    read_connections,
)

TCP_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
    "   uid  timeout inode"
)


def test_ipv4_loopback_listen_decodes() -> None:
    # 0100007F is 127.0.0.1 in little-endian; 0050 is port 80 in big-endian.
    assert decode_address("0100007F:0050", "ipv4") == ("127.0.0.1", 80)


def test_ipv6_loopback_decodes() -> None:
    assert decode_address("00000000000000000000000001000000:0050", "ipv6") == ("::1", 80)


def test_tcp_table_parses_state_and_inode() -> None:
    row = "0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 4242 1"
    text = f"{TCP_HEADER}\n   0: {row}\n"
    (conn,) = parse_table(text, "tcp", "ipv4")
    assert conn.source == "127.0.0.1" and conn.source_port == 80
    assert conn.state == "LISTEN"
    assert conn.inode == 4242
    assert conn.pid is None  # owner is attached separately


def test_udp_table_uses_unconn_state() -> None:
    text = f"{TCP_HEADER}\n   0: 00000000:0035 00000000:0000 07 0 0 0 0 0 99\n"
    (conn,) = parse_table(text, "udp", "ipv4")
    assert conn.state == "UNCONN"
    assert conn.destination_port == 0


def test_unknown_state_is_kept_not_dropped() -> None:
    text = f"{TCP_HEADER}\n   0: 0100007F:0050 00000000:0000 FF 0 0 0 0 0 1\n"
    (conn,) = parse_table(text, "tcp", "ipv4")
    assert conn.state == "FF"


def test_short_lines_are_skipped() -> None:
    assert parse_table(f"{TCP_HEADER}\ngarbage\n", "tcp", "ipv4") == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, NetworkMode.OFFLINE),
        ("", NetworkMode.OFFLINE),
        ("controlled", NetworkMode.CONTROLLED),
        ("ISOLATED", NetworkMode.ISOLATED),
        ("internet", NetworkMode.OFFLINE),  # unknown never opens the network
    ],
)
def test_network_mode_defaults_to_offline(value: str | None, expected: NetworkMode) -> None:
    assert parse_network_mode(value) is expected


def test_owner_is_attached_from_fake_proc(tmp_path: Path) -> None:
    net = tmp_path / "net"
    net.mkdir()
    (net / "tcp").write_text(
        f"{TCP_HEADER}\n   0: 0100007F:0050 00000000:0000 0A 0 0 0 0 0 4242\n"
    )
    (net / "tcp6").write_text(TCP_HEADER + "\n")
    (net / "udp").write_text(TCP_HEADER + "\n")
    (net / "udp6").write_text(TCP_HEADER + "\n")
    pid_dir = tmp_path / "777"
    (pid_dir / "fd").mkdir(parents=True)
    (pid_dir / "comm").write_text("listener\n")
    try:
        (pid_dir / "fd" / "3").symlink_to("socket:[4242]")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation needs privileges on this system")
    conns = read_connections(tmp_path)
    assert len(conns) == 1
    assert conns[0].pid == 777 and conns[0].process == "listener"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs a real /proc")
def test_live_read_does_not_crash() -> None:
    assert isinstance(read_connections(Path("/proc")), list)
