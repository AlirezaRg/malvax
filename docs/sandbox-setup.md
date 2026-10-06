# Sandbox setup (reproduction guide)

This guide reproduces the dynamic analysis path used in the project. It is for a laboratory only.

## What runs where
- **Controller (WSL Ubuntu on the Windows host):** Python, the MalvaX package, `scripts/run_lab_sample.py`.
  It calls the Windows `vmrun.exe` and the Windows OpenSSH client (`ssh.exe`, `scp.exe`).
- **Analysis VM (VMware Workstation, Ubuntu guest):** runs the sample under the collector.
  Network is host-only (no route to the Internet).
- **Host Windows:** VMware, the host-only virtual network, and the key store.

The sample never runs on the Windows host or on the WSL controller.

## Guest preparation (once)
1. Install Ubuntu Server or Desktop with a minimal package set. Python 3.11 or newer must be present.
2. Create an unprivileged account for analysis (no sudo, no docker, no lxd group):
   `sudo adduser --disabled-password --gecos "" malvax-agent`
   Set its password hash to a non-usable value: `sudo usermod -p '*' malvax-agent`.
3. Create the incoming area owned by that account:
   `sudo install -d -m 755 -o malvax-agent -g malvax-agent /analysis/incoming`
4. Install the controller public key for that account only (authorized_keys, mode 600).
5. Disable VMware Tools shared folders and drag-and-drop, and use a host-only network adapter.
6. Shut the VM down cleanly, then take the snapshot used for analysis (here `clean-v3`).
   The snapshot must be taken AFTER step 4. A snapshot taken before the key was installed
   does not contain it, and every revert then removes the key.

## Controller configuration (environment variables)
```
MALVAX_SANDBOX_PROVIDER=vmware          # required; "host" is refused, unknown names are refused
MALVAX_VMX_PATH='D:\...\guest.vmx'      # Windows path of the VM
MALVAX_SNAPSHOT_NAME=clean-v3
MALVAX_GUEST_HOST=<guest host-only IP>
MALVAX_GUEST_USER=malvax-agent
MALVAX_SSH_KEY='C:\Users\<you>\.ssh\malvax_sandbox'   # Windows path, owner-only ACL
MALVAX_EXECUTION_TIMEOUT=60             # seconds; refused above 3600
MALVAX_NETWORK_MODE=OFFLINE             # default; any other value falls back to OFFLINE
```
Why the Windows OpenSSH binaries are used from WSL: the guest's sshd throttled connections from
the WSL NAT address after several failed attempts. Connections from the Windows host were not
affected. Override with `MALVAX_SSH_BIN` / `MALVAX_SCP_BIN` if needed (not yet wired; the paths
are fixed in `malvax/sandbox_vmware.py`).

## Run one sample
From WSL, in the repository directory:
```
python3 scripts/run_lab_sample.py /mnt/c/.../lab_samples/file_activity/create_temp_file.sh
```
Result: `experiments/runs/<sha256>/telemetry-<ns>.json` and a summary on stdout.

## Run the batch
```
bash scripts/run_batch.sh 3
```
Writes `experiments/runs/batch/<sample>_run<i>.{summary,telemetry}.json`.

## What one run does
1. Revert the VM to the snapshot; start it; wait until SSH answers.
2. Copy the stdlib-only collector and the four modules it needs into the guest.
3. Copy the sample in under `/analysis/incoming/<sha256>`.
4. Run the collector, which runs the sample under `ulimit` and timeout, polls processes and
   sockets every 0.2 s, and diffs `/tmp` before and after.
5. Copy the telemetry JSON back to the controller.
6. Stop the VM (hard) and revert to the snapshot. This happens in a `finally` block, so it also
   happens after a failure.

## Known limits of this setup
- The guest is an Ubuntu VM on VMware with a host-only network. It is not a hardened sandbox;
  a hypervisor or guest-kernel escape is outside what this setup protects against.
- Process visibility is polling (0.2 s). Shorter-lived children can be missed.
- Filesystem visibility is a diff of `/tmp` only.
- System calls are not collected (`strace` is not installed in the guest; installing it needs
  root, which the analysis account does not have).
