"""Sandbox execution layer (Phase 1 of the sandbox integration).

Design rules enforced here:
- A sample is never executed on the host. There is no host provider, and an unknown or missing
  provider name is an error, never a silent fallback.
- Each run starts from a clean snapshot, and cleanup runs in a `finally` block even when the
  run fails, times out, or raises.
- Network defaults to OFFLINE. Enabling anything else must be explicit in the configuration.

The lifecycle (`run_sample`) talks only to the SandboxProvider protocol, so it can be tested with
MockSandboxProvider and run against a real VM with VMwareProvider (malvax/sandbox_vmware.py).
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from malvax.net_monitor import NetworkMode, parse_network_mode

KNOWN_PROVIDERS = frozenset({"vmware", "mock"})


class SandboxError(RuntimeError):
    """Any failure of the sandbox layer. Its message is safe to show to the user."""


class SandboxConfigError(SandboxError):
    """The sandbox configuration is missing, unknown, or unsafe."""


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    timeout_s: int = 60
    max_processes: int = 100
    max_memory_mb: int = 512
    max_cpu_s: int = 60
    max_output_mb: int = 100
    max_disk_mb: int = 200

    def __post_init__(self) -> None:
        for name in ("timeout_s", "max_processes", "max_memory_mb", "max_cpu_s",
                     "max_output_mb", "max_disk_mb"):
            if getattr(self, name) <= 0:
                raise SandboxConfigError(f"{name} must be a positive integer")
        if self.timeout_s > 3600:
            raise SandboxConfigError("timeout_s above one hour is refused")


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    provider: str
    snapshot: str
    limits: ExecutionLimits = field(default_factory=ExecutionLimits)
    network: NetworkMode = NetworkMode.OFFLINE
    vmx_path: str = ""
    guest_user: str = "malvax-agent"
    guest_host: str = ""
    ssh_key_path: str = ""
    incoming_dir: str = "/analysis/incoming"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SandboxConfig:
        source = os.environ if env is None else env
        provider = source.get("MALVAX_SANDBOX_PROVIDER", "").strip().lower()
        if not provider:
            raise SandboxConfigError("MALVAX_SANDBOX_PROVIDER is not set; refusing to run")
        if provider == "host":
            raise SandboxConfigError("host execution is not allowed")
        if provider not in KNOWN_PROVIDERS:
            raise SandboxConfigError(f"unknown sandbox provider {provider!r}")
        limits = ExecutionLimits(
            timeout_s=int(source.get("MALVAX_EXECUTION_TIMEOUT", "60")),
            max_processes=int(source.get("MALVAX_MAX_PROCESSES", "100")),
            max_memory_mb=int(source.get("MALVAX_MAX_MEMORY_MB", "512")),
            max_cpu_s=int(source.get("MALVAX_MAX_CPU_S", "60")),
            max_output_mb=int(source.get("MALVAX_MAX_OUTPUT_MB", "100")),
            max_disk_mb=int(source.get("MALVAX_MAX_DISK_MB", "200")),
        )
        return cls(
            provider=provider,
            snapshot=source.get("MALVAX_SNAPSHOT_NAME", "clean-v1"),
            limits=limits,
            network=parse_network_mode(source.get("MALVAX_NETWORK_MODE")),
            vmx_path=source.get("MALVAX_VMX_PATH", ""),
            guest_user=source.get("MALVAX_GUEST_USER", "malvax-agent"),
            guest_host=source.get("MALVAX_GUEST_HOST", ""),
            ssh_key_path=source.get("MALVAX_SSH_KEY", ""),
        )


@dataclass(frozen=True, slots=True)
class RunResult:
    exit_code: int | None
    timed_out: bool
    stdout: bytes
    stderr: bytes


class SandboxProvider(Protocol):
    """Everything the lifecycle needs from a hypervisor backend."""

    name: str

    def revert(self, snapshot: str) -> None: ...
    def start(self) -> None: ...
    def wait_ready(self, timeout_s: int) -> None: ...
    def copy_in(self, local: Path, remote: str) -> None: ...
    def run(self, argv: list[str], timeout_s: int) -> RunResult: ...
    def copy_out(self, remote: str, local: Path) -> None: ...
    def stop(self) -> None: ...


def make_provider(config: SandboxConfig) -> SandboxProvider:
    if config.provider == "mock":
        from malvax.sandbox_mock import MockSandboxProvider

        return MockSandboxProvider()
    if config.provider == "vmware":
        from malvax.sandbox_vmware import VMwareProvider

        return VMwareProvider(config)
    raise SandboxConfigError(f"unknown sandbox provider {config.provider!r}")


def guest_command(limits: ExecutionLimits, remote: str) -> list[str]:
    """One shell line for the guest: apply ulimit, make the sample executable, then exec it.

    Every number comes from validated integers in ExecutionLimits, and the path is the
    fixed incoming location built from a verified sha256. No sample-controlled text is
    interpolated into the command.
    """
    # bash (not dash) is used because only bash supports ulimit -u. Each limit has its own call.
    script = (
        f"ulimit -t {limits.max_cpu_s} && "
        f"ulimit -u {limits.max_processes} && "
        f"ulimit -v {limits.max_memory_mb * 1024} && "
        f"ulimit -f {limits.max_disk_mb * 1024} && "
        'chmod 500 "$1" && exec "$1"'
    )
    return ["bash", "-c", script, "bash", remote]


def run_sample(provider: SandboxProvider, config: SandboxConfig, sample: Path,
               sha256: str) -> RunResult:
    """Run one sample in a clean VM. The VM is reverted and stopped in every case."""
    if not sample.is_file():
        raise SandboxError("sample file does not exist")
    if not all(c in "0123456789abcdef" for c in sha256) or len(sha256) != 64:
        raise SandboxError("sha256 must be 64 lowercase hex characters")
    remote = f"{config.incoming_dir}/{sha256}"
    try:
        provider.revert(config.snapshot)
        provider.start()
        provider.wait_ready(timeout_s=120)
        provider.copy_in(sample, remote)
        return provider.run(guest_command(config.limits, remote), config.limits.timeout_s)
    finally:
        try:
            provider.stop()
        finally:
            provider.revert(config.snapshot)


REMOTE_TOOLS = "/analysis/incoming/_tools"
TOOL_MODULES = ("__init__.py", "fs_monitor.py", "process_monitor.py", "net_monitor.py",
                "sandbox.py", "guest_collector.py")


def run_collected(provider: SandboxProvider, config: SandboxConfig, sample: Path, sha256: str,
                  package_dir: Path, out_dir: Path) -> Path:
    """Run one sample in a clean VM and retrieve its telemetry JSON.

    The guest gets a copy of the small stdlib-only collector. The collector runs the sample under
    limits and writes telemetry; the controller copies that file back and stores it under out_dir.
    The VM is reverted in every case.
    """
    if not sample.is_file():
        raise SandboxError("sample file does not exist")
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        raise SandboxError("sha256 must be 64 lowercase hex characters")
    remote_sample = f"{config.incoming_dir}/{sha256}"
    remote_out = f"{config.incoming_dir}/{sha256}.telemetry.json"
    # One file per run, so repeated runs of the same sample never overwrite each other.
    local_out = out_dir / sha256 / f"telemetry-{time.time_ns()}.json"
    try:
        provider.revert(config.snapshot)
        provider.start()
        provider.wait_ready(timeout_s=120)
        provider.run(["mkdir", "-p", f"{REMOTE_TOOLS}/malvax"], timeout_s=30)
        for name in TOOL_MODULES:
            provider.copy_in(package_dir / name, f"{REMOTE_TOOLS}/malvax/{name}")
        provider.copy_in(sample, remote_sample)
        collect_argv = [
            "env", f"PYTHONPATH={REMOTE_TOOLS}", "python3", "-m", "malvax.guest_collector",
            "--sample", remote_sample, "--sha256", sha256, "--watch", "/tmp",
            "--out", remote_out, "--timeout", str(config.limits.timeout_s),
        ]
        collected = provider.run(collect_argv, timeout_s=config.limits.timeout_s + 60)
        if collected.exit_code != 0:
            raise SandboxError(f"telemetry collector exited with {collected.exit_code}")
        local_out.parent.mkdir(parents=True, exist_ok=True)
        provider.copy_out(remote_out, local_out)
        return local_out
    finally:
        try:
            provider.stop()
        finally:
            provider.revert(config.snapshot)
