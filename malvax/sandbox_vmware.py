"""VMware Workstation provider (Phase 2).

The controller runs in WSL and calls the Windows vmrun.exe through WSL interop. The guest is
reached over SSH with a dedicated key for the unprivileged guest account. Every subprocess is
started with an argument list (never a shell string), so no value from a sample is interpreted
by a shell on the host.
"""

from __future__ import annotations

import shlex
import subprocess
import time

from malvax.sandbox import RunResult, SandboxConfig, SandboxConfigError, SandboxError

DEFAULT_VMRUN = "/mnt/c/Program Files/VMware/VMware Workstation/vmrun.exe"
# The controller runs in WSL, but sshd sometimes throttles WSL's own source address after failed
# attempts. The Windows OpenSSH client uses the Windows address and avoids that. Both paths can be
# overridden with MALVAX_SSH_BIN and MALVAX_SCP_BIN.
DEFAULT_SSH = "/mnt/c/Windows/System32/OpenSSH/ssh.exe"
DEFAULT_SCP = "/mnt/c/Windows/System32/OpenSSH/scp.exe"
_SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes"]


def _windows_path(path: str) -> str:
    """Map /mnt/c/... (WSL) to C:/... so the Windows scp.exe can read it."""
    if path.startswith("/mnt/") and len(path) > 6 and path[5].isalpha() and path[6] == "/":
        return f"{path[5].upper()}:{path[6:]}"
    return path


class VMwareProvider:
    name = "vmware"

    def __init__(self, config: SandboxConfig, vmrun: str = DEFAULT_VMRUN,
                 ssh_bin: str = DEFAULT_SSH, scp_bin: str = DEFAULT_SCP) -> None:
        if not config.vmx_path or not config.guest_host or not config.ssh_key_path:
            raise SandboxConfigError(
                "vmware provider needs MALVAX_VMX_PATH, MALVAX_GUEST_HOST and MALVAX_SSH_KEY"
            )
        self._config = config
        self._vmrun = vmrun
        self._ssh = ssh_bin
        self._scp = scp_bin

    def _vmrun_call(self, *args: str, timeout_s: int = 120) -> str:
        try:
            done = subprocess.run([self._vmrun, *args], capture_output=True, text=True,
                                  timeout=timeout_s, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxError(f"vmrun {args[0]} failed to run") from exc
        if done.returncode != 0:
            raise SandboxError(f"vmrun {args[0]} exited with {done.returncode}")
        return done.stdout

    def _ssh_base(self) -> list[str]:
        return [self._ssh, *_SSH_OPTIONS, "-i", self._config.ssh_key_path,
                f"{self._config.guest_user}@{self._config.guest_host}"]

    def revert(self, snapshot: str) -> None:
        self._vmrun_call("revertToSnapshot", self._config.vmx_path, snapshot)

    def start(self) -> None:
        self._vmrun_call("start", self._config.vmx_path, "nogui")

    def wait_ready(self, timeout_s: int) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                done = subprocess.run([*self._ssh_base(), "true"], capture_output=True,
                                      timeout=15, check=False)
                if done.returncode == 0:
                    return
            except subprocess.TimeoutExpired:
                pass
            time.sleep(3)
        raise SandboxError("guest did not become reachable over SSH before the boot timeout")

    def copy_in(self, local, remote: str) -> None:  # type: ignore[no-untyped-def]
        target = f"{self._config.guest_user}@{self._config.guest_host}:{remote}"
        cmd = [self._scp, *_SSH_OPTIONS, "-i", self._config.ssh_key_path,
               _windows_path(str(local)), target]
        done = subprocess.run(cmd, capture_output=True, timeout=120, check=False)
        if done.returncode != 0:
            raise SandboxError("sample transfer to the guest failed")

    def run(self, argv: list[str], timeout_s: int) -> RunResult:
        # shlex.join quotes every element, so the remote shell receives exactly these words.
        remote_cmd = shlex.join(argv)
        try:
            done = subprocess.run([*self._ssh_base(), remote_cmd], capture_output=True,
                                  timeout=timeout_s, check=False)
            return RunResult(exit_code=done.returncode, timed_out=False,
                             stdout=done.stdout, stderr=done.stderr)
        except subprocess.TimeoutExpired as exc:
            return RunResult(exit_code=None, timed_out=True,
                             stdout=exc.stdout or b"", stderr=exc.stderr or b"")

    def copy_out(self, remote: str, local) -> None:  # type: ignore[no-untyped-def]
        source = f"{self._config.guest_user}@{self._config.guest_host}:{remote}"
        cmd = [self._scp, *_SSH_OPTIONS, "-i", self._config.ssh_key_path, source,
               _windows_path(str(local))]
        done = subprocess.run(cmd, capture_output=True, timeout=120, check=False)
        if done.returncode != 0:
            raise SandboxError("retrieving results from the guest failed")

    def stop(self) -> None:
        self._vmrun_call("stop", self._config.vmx_path, "hard")
