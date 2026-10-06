# Sandbox Security

**No software sandbox can guarantee perfect isolation.** MalvaX relies on layers so that a
single failure does not expose the host. None of the layers below has been tested against a
real malicious sample yet, because Phase 4 is not implemented.

## Why a VM, and why Docker alone is not enough

- A container shares the host kernel. A kernel exploit reached from a sample is a host
  exploit. Docker's namespaces, seccomp and capabilities reduce attack surface but do not
  remove the shared kernel.
- A VM runs a separate kernel behind a hypervisor. An escape requires a hypervisor bug, which
  is a harder target than a kernel bug.
- Therefore the sample runs only in a dedicated VM. Docker Compose hosts the backend, DB,
  Redis and monitoring, and never runs sample code.

## Layers (defence in depth)

1. Dedicated VM with snapshot `clean-v1`, restored before every run.
2. Sample runs as an unprivileged user; the analysis agent is not root.
3. rlimits (CPU, memory, processes, file size) and a controller-side wall-clock timeout.
4. OFFLINE network by default. No default route; lab DNS/HTTP only in ISOLATED/CONTROLLED.
5. No shared folders, clipboard, or host-home mounts.
6. Telemetry is sent out of the guest by the agent and stored by the controller, so an attacker
   inside the guest cannot erase the logs held on the host.
7. Revert the VM after each run and never reuse a possibly contaminated VM.

## Phase 1 status

Phase 1 never executes a sample. The only code that touches sample bytes reads them to hash
and to check magic numbers (`malvax/intake.py`). This is verified by tests but is not a
sandbox claim.
