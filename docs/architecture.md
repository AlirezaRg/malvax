# MalvaX Architecture

## 1. Environment analysis (as of this commit)

- Host: Windows 11 Enterprise. Python 3.12 available. Docker 29 available. Cygwin `strace` present on the host, but **not** usable for Linux sample execution.
- Not available on the host: QEMU/KVM, YARA binary, a Linux analysis VM. These are prerequisites for Phases 4+ and are **not yet set up**.
- Consequence: Phase 1 (sample intake) is pure Python and runs anywhere. Nothing in Phase 1 executes a sample.

## 2. Components and trust boundaries

```
 Host (Windows, trusted controller)            Analysis VM (Linux, untrusted after execution)
 ┌────────────────────────────────────┐        ┌──────────────────────────────────────────┐
 │ MalvaX Controller                  │  SSH/  │ Analysis Agent (root-less)               │
 │  - intake (hashes, metadata)       │ vsock  │  - copies sample in                      │
 │  - SQLite/PostgreSQL store         │ ─────► │  - runs sample under timeout + rlimits   │
 │  - lifecycle state machine         │        │  - collects /proc, inotify, strace logs  │
 │  - static analysis, YARA           │ ◄───── │ Sample (untrusted)                       │
 │  - behavior engine, risk, report   │ result │ Isolated virtual NIC → simulated network │
 └────────────────────────────────────┘ bundle └──────────────────────────────────────────┘
          Trust boundary ▲                              Reverted to snapshot after each run
```

The controller never executes sample code. The only data crossing the boundary is:
the sample file (controller → VM) and a telemetry bundle (VM → controller). The telemetry
bundle is parsed as **untrusted input**.

## 3. Analysis lifecycle

```
SUBMITTED → QUEUED → STATIC_ANALYSIS → SANDBOX_PREPARATION → EXECUTING
          → BEHAVIOR_COLLECTION → ANALYSIS → REPORT_GENERATION → COMPLETED
Failure states: FAILED, TIMEOUT (from EXECUTING/BEHAVIOR_COLLECTION), CANCELLED
```

Implemented in `malvax/lifecycle.py`. `SampleStore.transition()` validates each change against
`ALLOWED_TRANSITIONS` and appends a row to `state_transitions`. Terminal states have no
outgoing transitions. Illegal transitions raise `InvalidTransitionError`.

## 4. Sample intake (Phase 1, implemented)

`malvax/intake.py`:

1. Reject non-regular files, empty files, and files above `max_bytes` (default 50 MiB).
2. Stream the file once to compute SHA-256 (primary ID), SHA-1 and MD5.
3. Identify the type from magic bytes only: `\x7fELF` → ELF, `#!` → SCRIPT, `PK\x03\x04` → ZIP.
   No `file(1)` subprocess is used, so no external parser touches the sample.
4. Sanitize the user-supplied filename to a basename of `[A-Za-z0-9._-]`, max 200 chars. The
   filename is stored as metadata only and is never used to build a path or a command.
5. Store a row keyed by a random UUID. A repeated SHA-256 returns the existing row.

The sample is never executed during upload.

## 5. Data model (target PostgreSQL; SQLite in Phase 1)

| Table | Phase 1 | Purpose |
|---|---|---|
| `samples` | yes | id, filename, size, sha256 (unique), sha1, md5, file_type, uploaded_at, analysis_status |
| `state_transitions` | yes | append-only lifecycle log (sample_id, from_state, to_state, changed_at) |
| `analysis_jobs` | Phase 12 | job id, sample id, state, sandbox profile, limits, timestamps |
| `static_results` | Phase 2 | ELF fields, sections, imports, mitigations (JSON) |
| `yara_matches` | Phase 3 | rule id, severity, offsets |
| `behavior_events` | Phase 9 | normalized events with evidence reference |
| `process_events`, `filesystem_events`, `network_events` | Phases 5–7 | raw telemetry, retention-limited |
| `findings` | Phase 9–10 | finding id, category, score contribution, evidence ids |
| `reports` | Phase 11 | JSON document + rendered HTML/PDF paths |
| `users`, `audit_logs` | Phase 14 | accounts (argon2 hashes only), audit trail |

Retention: raw telemetry tables carry an `expires_at` column; a periodic job deletes expired
rows. The retention period is configuration, not code.

## 6. Sandbox architecture (Phase 4 design, not implemented)

- Dedicated Linux VM (QEMU/KVM or VirtualBox), not a container.
- Snapshot `clean-v1` taken with the agent installed and no network. Every run restores it.
- Analysis agent runs as an unprivileged user inside the guest; the sample runs as a second
  unprivileged user with `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_FSIZE`, and a
  wall-clock timeout enforced by the controller.
- Network modes: `OFFLINE` (default, no NIC), `ISOLATED` (host-only network with lab DNS and HTTP),
  `CONTROLLED` (allow-list routed through a monitor). No default route to the Internet.
- Shared folders, clipboard and host-home mounts are disabled.
- See `docs/sandbox-security.md` for the threat analysis.

## 7. Laboratory samples (Phase 1 defines the plan; code arrives in Phase 4)

```
lab_samples/
├── benign/          exits 0, prints a line, no side effects
├── file_activity/   creates and modifies a file under a temp dir it owns
├── process_activity/ runs a fixed, predictable process tree (fork + exec of /bin/true)
├── network_activity/ connects to 127.0.0.1 test HTTP server only
├── dns_activity/    resolves a name against the lab resolver only
├── child_process/   spawns one child that exits
└── mixed_behavior/  combination of the above, deterministic order
```

Each sample must be deterministic, must refuse to run unless the lab environment variable
is set, and must never touch paths outside its own temp directory.

## 8. Roadmap and status

| Phase | Scope | Status |
|---|---|---|
| 1 | Architecture, sample intake, lifecycle, store | **Implemented, 17 tests passing** |
| 2 | Hashing (done in 1) and static ELF analysis | Not started |
| 3 | Strings and YARA | Not started |
| 4 | Sandbox VM controller | Blocked on Linux VM setup |
| 5–8 | Process, filesystem, network, syscall monitoring | Not started |
| 9–10 | Behavior correlation, risk scoring | Not started |
| 11 | Report generation (JSON first, then HTML/PDF) | Not started |
| 12–14 | FastAPI backend, auth, audit logging | Not started |
| 13 | Next.js frontend | Not started |
| 15 | AI analyst (structured evidence only) | Not started |
| 16 | Prometheus / Grafana | Not started |
| 17–19 | Tests expansion, experiments, documentation | Partial (docs in progress) |

Measurements: **NOT YET MEASURED**. No performance, accuracy or benchmark figures exist yet.
