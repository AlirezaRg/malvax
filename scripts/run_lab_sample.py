"""Run one laboratory sample inside the disposable VM with telemetry collection.

Run from WSL (the controller). The sample executes inside the guest under the collector, never on
the host. Results are stored under experiments/runs/<sha256>/telemetry.json.

Usage (configuration comes from the environment, see docs/sandbox-setup.md):
    python scripts/run_lab_sample.py /mnt/c/.../lab_samples/file_activity/create_temp_file.sh
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from malvax.sandbox import SandboxConfig, make_provider, run_collected  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: run_lab_sample.py <sample-path>", file=sys.stderr)
        return 2
    sample = Path(argv[1])
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    config = SandboxConfig.from_env()
    provider = make_provider(config)
    out_dir = ROOT / "experiments" / "runs"
    telemetry_path = run_collected(provider, config, sample, digest,
                                   package_dir=ROOT / "malvax", out_dir=out_dir)

    telemetry = json.loads(telemetry_path.read_text(encoding="utf-8"))
    meta = telemetry["execution_metadata"]
    summary = {
        "sample": sample.name,
        "sha256": digest,
        "snapshot": config.snapshot,
        "network": config.network.value,
        "exit_code": meta["exit_code"],
        "timeout": meta["timeout"],
        "sample_stdout": meta["stdout_text"],
        "process_events": len(telemetry["process_events"]),
        "filesystem_events": [(e["operation"], e["path"]) for e in telemetry["filesystem_events"]],
        "network_sockets_seen": len(telemetry["network_events"]),
        "syscall_events": telemetry["syscall_events"],
        "telemetry_file": str(telemetry_path.relative_to(ROOT)),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if meta["exit_code"] == 0 and not meta["timeout"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
