# Evaluation

## What is measured and what is not
| Quantity | Status |
|---|---|
| Static analysis time (per stage, per sample) | Measured (`experiments/static_eval.py`, Windows and Debian) |
| Static detection consistency on the synthetic set | Measured, with the caveat below |
| Dynamic run: execution success, exit code, timeout | Measured (`experiments/runs/batch/`) |
| Dynamic run: process, filesystem and socket observations | Measured on the lab samples (see below) |
| Dynamic run: wall time | Measured per run (summary files) |
| Static + dynamic combined detection | Not evaluated against labels (see "Not done") |
| Detection rate on real malware | **NOT_MEASURED** (no real malware was used, by design) |
| False-positive rate on real software | **NOT_MEASURED** |
| System-call observations | **NOT_MEASURED** (not collected) |

## Lab samples
Each sample is written by the author and does one harmless, observable thing:
- `file_activity/create_temp_file.sh`: creates `/tmp/malvax-lab-test.txt`.
- `child_process/spawn_child.sh`: starts one child (`sleep 2`) and waits for it.
- `network_activity/local_listener.sh`: starts an HTTP listener on `127.0.0.1` only, fetches from it, stops it.

## Method
- Each sample runs inside the VM from the same snapshot, once per repetition (3 repetitions).
- The collector records process events (polling), filesystem diff of `/tmp`, and sample-owned
  sockets observed during the run.
- Expected behavior is recorded by the author in the sample comment. It is used only to compare
  results after the run. The detector never reads it.

## Static evaluation (synthetic set, Windows)
Two detector criteria were run. The first (severity low or higher) missed a severity-info marker.
The second (any YARA match or any string indicator) matched every label. The second was adopted
after seeing the first, so its perfect score is **not** evidence of detection performance.

## Results: dynamic runs (9 real runs, inside the VM)
Raw telemetry: `experiments/runs/batch/*.telemetry.json`. Generated table: `experiments/runs/batch/SUMMARY.md`.

| run | exit | timeout | processes | fs changes | sockets (attributed) | findings | dynamic risk | wall s |
|---|---|---|---|---|---|---|---|---|
| create_temp_file_run1 | 0 | False | 1 | CREATE malvax-lab-test.txt | 0 | - | 4 | 0.233 |
| create_temp_file_run2 | 0 | False | 1 | CREATE malvax-lab-test.txt | 0 | - | 4 | 0.231 |
| create_temp_file_run3 | 0 | False | 1 | CREATE malvax-lab-test.txt | 0 | - | 4 | 0.241 |
| local_listener_run1 | 0 | False | 3 | - | 1 | CHILD_PROCESS, CHILD_PROCESS | 11 | 2.121 |
| local_listener_run2 | 0 | False | 3 | - | 1 | CHILD_PROCESS, CHILD_PROCESS | 11 | 2.119 |
| local_listener_run3 | 0 | False | 3 | - | 1 | CHILD_PROCESS, CHILD_PROCESS | 11 | 2.127 |
| spawn_child_run1 | 0 | False | 2 | - | 0 | CHILD_PROCESS | 7 | 2.095 |
| spawn_child_run2 | 0 | False | 2 | - | 0 | CHILD_PROCESS | 7 | 2.092 |
| spawn_child_run3 | 0 | False | 2 | - | 0 | CHILD_PROCESS | 7 | 2.117 |

All runs: snapshot clean-v3, network OFFLINE (host-only), 60 s timeout, 3 repetitions per sample.
Syscalls: NOT_COLLECTED. Sample counts are per run and not statistical evidence.

An earlier batch (`experiments/runs/batch_v1_sockets_after_exit/`) recorded sockets only after the
sample exited. It attributed 0 sockets to the listener sample, which was a real collection gap. The
collector now observes sockets during the run, and the table above comes from the corrected run.

## Reproducibility
- Snapshot, sample hashes, VM name, configuration and the commit hash are recorded with each run.
- Repeat with `bash scripts/run_batch.sh 3` (see `docs/sandbox-setup.md`).

## Limitations of this evaluation
- Three benign samples and three repetitions are far too few for rates or confidence intervals.
- Labels are the author's expectations, not ground truth from an independent source.
- Results describe one VM on one host. They do not transfer to other hardware or hypervisors.
