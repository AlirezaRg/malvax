#!/usr/bin/env bash
# Run each laboratory sample N times inside the VM, one collected run per invocation.
# Usage (from WSL): bash scripts/run_batch.sh <runs-per-sample>
set -u
runs="${1:-3}"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/experiments/runs/batch"
mkdir -p "$out"
for sample in file_activity/create_temp_file.sh child_process/spawn_child.sh network_activity/local_listener.sh; do
  name="$(basename "$sample" .sh)"
  for i in $(seq 1 "$runs"); do
    python3 "$root/scripts/run_lab_sample.py" "$root/lab_samples/$sample" > "$out/${name}_run${i}.summary.json" 2>&1
    rc=$?
    telemetry="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['telemetry_file'])" "$out/${name}_run${i}.summary.json" 2>/dev/null || true)"
    echo "$name run$i rc=$rc telemetry=$telemetry"
    if [ -n "$telemetry" ]; then cp "$root/$telemetry" "$out/${name}_run${i}.telemetry.json"; fi
  done
done
echo BATCH_DONE
