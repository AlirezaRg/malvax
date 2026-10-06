"""Sandbox safety tests (Phase 1). They use MockSandboxProvider and never touch a real VM."""

import shlex
from pathlib import Path

import pytest

from malvax.net_monitor import NetworkMode
from malvax.sandbox import (
    ExecutionLimits,
    RunResult,
    SandboxConfig,
    SandboxConfigError,
    SandboxError,
    guest_command,
    run_sample,
)
from malvax.sandbox_mock import MockSandboxProvider
from malvax.sandbox_vmware import VMwareProvider

SHA = "ab" * 32


def _config(**overrides) -> SandboxConfig:
    base = dict(provider="mock", snapshot="clean-v1", limits=ExecutionLimits(timeout_s=30))
    base.update(overrides)
    return SandboxConfig(**base)


def _sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF" + b"\x00" * 16)
    return path


# ---- configuration: nothing runs unless it is explicit and known -----------------------------

def test_missing_provider_is_refused() -> None:
    with pytest.raises(SandboxConfigError, match="not set"):
        SandboxConfig.from_env({})


def test_host_execution_is_refused() -> None:
    with pytest.raises(SandboxConfigError, match="host execution is not allowed"):
        SandboxConfig.from_env({"MALVAX_SANDBOX_PROVIDER": "host"})


def test_unknown_provider_is_refused_not_silently_replaced() -> None:
    with pytest.raises(SandboxConfigError, match="unknown sandbox provider"):
        SandboxConfig.from_env({"MALVAX_SANDBOX_PROVIDER": "qemu-fallback"})


def test_network_defaults_to_offline() -> None:
    cfg = SandboxConfig.from_env({"MALVAX_SANDBOX_PROVIDER": "mock"})
    assert cfg.network is NetworkMode.OFFLINE


def test_unparseable_network_mode_falls_back_to_offline() -> None:
    cfg = SandboxConfig.from_env({"MALVAX_SANDBOX_PROVIDER": "mock",
                                  "MALVAX_NETWORK_MODE": "internet"})
    assert cfg.network is NetworkMode.OFFLINE


@pytest.mark.parametrize("field", ["timeout_s", "max_processes", "max_memory_mb"])
def test_non_positive_limits_are_refused(field: str) -> None:
    with pytest.raises(SandboxConfigError):
        ExecutionLimits(**{field: 0})


def test_excessive_timeout_is_refused() -> None:
    with pytest.raises(SandboxConfigError, match="one hour"):
        ExecutionLimits(timeout_s=7200)


def test_vmware_provider_needs_explicit_vm_and_key() -> None:
    with pytest.raises(SandboxConfigError, match="needs"):
        VMwareProvider(SandboxConfig(provider="vmware", snapshot="clean-v1"))


# ---- lifecycle: clean state before, cleanup after, in every case --------------------------------

def test_lifecycle_reverts_before_running_and_after(tmp_path: Path) -> None:
    provider = MockSandboxProvider()
    run_sample(provider, _config(), _sample(tmp_path), SHA)
    steps = [c[0] for c in provider.calls]
    assert steps == ["revert", "start", "wait_ready", "copy_in", "run", "stop", "revert"]
    assert provider.calls[0] == ("revert", "clean-v1")


def test_cleanup_runs_when_the_sample_run_fails(tmp_path: Path) -> None:
    provider = MockSandboxProvider(fail_at="run")
    with pytest.raises(RuntimeError, match="scripted failure at run"):
        run_sample(provider, _config(), _sample(tmp_path), SHA)
    steps = [c[0] for c in provider.calls]
    assert steps[-2:] == ["stop", "revert"]


def test_revert_still_runs_when_stop_fails(tmp_path: Path) -> None:
    provider = MockSandboxProvider(fail_at="stop")
    with pytest.raises(RuntimeError, match="scripted failure at stop"):
        run_sample(provider, _config(), _sample(tmp_path), SHA)
    assert provider.calls[-1] == ("revert", "clean-v1")


def test_timeout_is_reported_and_vm_still_reverted(tmp_path: Path) -> None:
    timed_out = RunResult(exit_code=None, timed_out=True, stdout=b"", stderr=b"")
    provider = MockSandboxProvider(run_result=timed_out)
    result = run_sample(provider, _config(), _sample(tmp_path), SHA)
    assert result.timed_out is True
    assert provider.calls[-1] == ("revert", "clean-v1")


def test_snapshot_failure_stops_before_any_sample_transfer(tmp_path: Path) -> None:
    provider = MockSandboxProvider(fail_at="revert")
    with pytest.raises(RuntimeError):
        run_sample(provider, _config(), _sample(tmp_path), SHA)
    assert not any(c[0] == "copy_in" for c in provider.calls)


# ---- inputs: nothing from the sample can reach a shell ------------------------------------------

@pytest.mark.parametrize("bad_sha", ["", "xyz", "AB" * 32, "ab" * 31, "ab; rm -rf /" + "a" * 40])
def test_malformed_sha256_is_refused(tmp_path: Path, bad_sha: str) -> None:
    with pytest.raises(SandboxError, match="sha256"):
        run_sample(MockSandboxProvider(), _config(), _sample(tmp_path), bad_sha)


def test_missing_sample_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SandboxError, match="does not exist"):
        run_sample(MockSandboxProvider(), _config(), tmp_path / "nope.bin", SHA)


def test_guest_command_uses_only_validated_numbers_and_fixed_path() -> None:
    remote = f"/analysis/incoming/{SHA}"
    argv = guest_command(ExecutionLimits(timeout_s=10, max_processes=5), remote)
    assert argv[:2] == ["bash", "-c"]
    script = argv[2]
    assert "ulimit -t 60" in script and "-u 5" in script
    assert argv[-1] == f"/analysis/incoming/{SHA}"


def test_remote_command_quoting_keeps_each_word_intact() -> None:
    hostile = "/analysis/incoming/x; touch /tmp/pwned $(id)"
    argv = guest_command(ExecutionLimits(), hostile)
    assert shlex.split(shlex.join(argv)) == argv  # one word per argument, nothing executed


def test_limits_come_from_configuration() -> None:
    cfg = SandboxConfig.from_env({"MALVAX_SANDBOX_PROVIDER": "mock",
                                  "MALVAX_EXECUTION_TIMEOUT": "42",
                                  "MALVAX_MAX_OUTPUT_MB": "7"})
    assert cfg.limits.timeout_s == 42
    assert cfg.limits.max_output_mb == 7
