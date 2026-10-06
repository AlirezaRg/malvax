import pytest

from malvax.syscall_monitor import (
    SECURITY_SYSCALLS,
    StraceError,
    build_strace_command,
    parse_strace_output,
)

SAMPLE_TRACE = """\
12:00:01.000001 execve("/tmp/sample", ["/tmp/sample"], 0x7ffd /* 20 vars */) = 0
12:00:01.000200 openat(AT_FDCWD, "/tmp/malvax-lab/out.txt", O_WRONLY|O_CREAT, 0644) = 3
[pid 4242] 12:00:01.000300 connect(5, {sa_family=AF_INET, sin_port=htons(443), \
sin_addr=inet_addr("10.0.0.5")}, 16) = -1 EINPROGRESS (Operation now in progress)
[pid 4242] 12:00:01.000400 unlinkat(AT_FDCWD, "/tmp/malvax-lab/out.txt", 0) = 0
12:00:01.000500 rename("/tmp/a", "/tmp/b") = 0
12:00:01.000600 setuid(0) = -1 EPERM (Operation not permitted)
12:00:01.000700 read(3, "data", 4) = 4
12:00:01.000800 openat(AT_FDCWD, "/tmp/x", O_RDONLY <unfinished ...>
12:00:01.000900 <... openat resumed>) = 4
this is not strace output
"""


def test_command_is_argument_list_with_filter() -> None:
    cmd = build_strace_command("/tmp/sample", "/tmp/out.log")
    assert isinstance(cmd, list)
    assert cmd[0] == "strace"
    assert "-f" in cmd and "-tt" in cmd
    filter_arg = cmd[cmd.index("-e") + 1]
    assert filter_arg == "trace=" + ",".join(SECURITY_SYSCALLS)
    assert cmd[-2:] == ["--", "/tmp/sample"]


@pytest.mark.parametrize("bad", ["sample", "", "/tmp/a\x00b"])
def test_non_absolute_or_nul_sample_is_refused(bad: str) -> None:
    with pytest.raises(StraceError):
        build_strace_command(bad, "/tmp/out.log")


def test_execve_path_and_timestamp() -> None:
    events = parse_strace_output(SAMPLE_TRACE).events
    first = events[0]
    assert first.name == "execve"
    assert first.path == "/tmp/sample"
    assert first.timestamp == "12:00:01.000001"
    assert first.pid is None


def test_openat_path_extracted() -> None:
    ev = parse_strace_output(SAMPLE_TRACE).events[1]
    assert ev.name == "openat"
    assert ev.path == "/tmp/malvax-lab/out.txt"
    assert ev.result == "3"


def test_connect_destination_and_port() -> None:
    ev = next(e for e in parse_strace_output(SAMPLE_TRACE).events if e.name == "connect")
    assert ev.destination == "10.0.0.5"
    assert ev.port == 443
    assert ev.pid == 4242


def test_unlinkat_and_rename_paths() -> None:
    events = parse_strace_output(SAMPLE_TRACE).events
    unlink = next(e for e in events if e.name == "unlinkat")
    rename = next(e for e in events if e.name == "rename")
    assert unlink.path == "/tmp/malvax-lab/out.txt"
    assert rename.path == "/tmp/a"  # source path is the first quoted argument


def test_failed_syscall_keeps_error_result() -> None:
    ev = next(e for e in parse_strace_output(SAMPLE_TRACE).events if e.name == "setuid")
    assert ev.result.startswith("-1 EPERM")


def test_unfinished_resumed_and_garbage_are_counted() -> None:
    result = parse_strace_output(SAMPLE_TRACE)
    assert result.unmatched == 3  # unfinished, resumed, and the garbage line


def test_non_security_calls_have_no_extracted_fields() -> None:
    ev = next(e for e in parse_strace_output(SAMPLE_TRACE).events if e.name == "read")
    assert ev.path is None and ev.destination is None and ev.port is None
