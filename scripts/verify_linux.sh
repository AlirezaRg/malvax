#!/usr/bin/env bash
# Verifies MalvaX on a Linux host (Debian). Parses only; never executes samples.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install -q -e ".[dev]"

echo "== pytest =="
python -m pytest -q

echo "== ruff =="
python -m ruff check .

echo "== ELF parser vs readelf on system binaries (parse-only, no execution) =="
for bin in /bin/ls /usr/bin/python3; do
    [ -f "$bin" ] || continue
    python - "$bin" <<'PY'
import subprocess, sys
from pathlib import Path
from malvax.elf import analyze_elf

path = sys.argv[1]
report = analyze_elf(Path(path))
readelf_needed = subprocess.run(
    ["readelf", "-d", path], capture_output=True, text=True, check=True
).stdout
expected = sorted(
    line.split("[", 1)[1].split("]", 1)[0]
    for line in readelf_needed.splitlines()
    if "(NEEDED)" in line
)
ok = sorted(report.needed_libraries) == expected
print(f"{path}: type={report.elf_type} interp={report.interpreter} "
      f"needed={len(report.needed_libraries)} readelf_match={ok} "
      f"mitigations={report.mitigations}")
if not ok:
    sys.exit(f"NEEDED mismatch for {path}: {report.needed_libraries} vs {expected}")
PY
done

echo "OK"
