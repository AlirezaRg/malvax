# MalvaX: Linux Malware Analysis and Behavioral Sandbox

MalvaX is a **defensive** academic platform. It analyzes suspicious Linux ELF files and turns what it observes into a structured, evidence-backed report. It does not create malware, and it does not run samples on the host. Use it only in an isolated laboratory.

> **Safety:** Do not run unknown samples on your own machine. The planned execution path is a dedicated, disposable VM with no default network. The sandbox controller is not connected yet, so dynamic results are not produced.

## Roadmap and status

| Phase | Scope | Status |
|---|---|---|
| 1 | Sample intake: SHA-256/SHA-1/MD5, type by magic bytes, lifecycle state machine | Done, tested on Linux |
| 2 | Static ELF analysis: headers, sections, imports, PIE/NX/RELRO/canary | Done, checked against `readelf` |
| 3 | Strings indicators and YARA with a modular rule tree | Done |
| 4 | Sandbox VM controller (revert, run, collect) | Done: real VM run from WSL, 9 runs with telemetry (see `docs/sandbox-setup.md`) |
| 5 | Process monitoring from `/proc` and process tree | Done |
| 6 | Filesystem monitoring by snapshot diff | Done |
| 7 | Network monitoring from `/proc/net` with owner attribution | Done |
| 8 | System-call monitoring with strace (security calls only) | Done (parser tested with hand-written traces) |
| 9 | Behavior correlation with documented rules and evidence | Done |
| 10 | Transparent risk score (capped components, reasons, evidence) | Done |
| 11 | Reports as JSON and HTML (untrusted text escaped) | Done; **PDF not built** |
| 12 | FastAPI backend, PostgreSQL, Redis queue, worker | Done |
| 13 | Next.js frontend (dashboard, samples, analyses, reports) | Done |
| 14 | Authentication: Admin, Analyst, Viewer roles; Argon2; JWT | Done |
| 15 | AI summary from structured evidence only, validated output | Done (offline by default) |
| 16 | Prometheus metrics, Grafana dashboard | Done |
| 17 | Tests: unit, API, worker, end-to-end pipeline | Done; coverage about 94% |
| 18 | Evaluation harness | Static and 9 real dynamic runs measured; combined static+dynamic detection **not measured** |
| 19 | Documentation (`docs/`) and defense questions | Done for setup, limitations, evaluation, defense; see `docs/` |

## What is not done yet

- System-call collection (`strace` needs root inside the guest).
- Combined static + dynamic detection measured against labels.
- Measured dynamic results and the static vs dynamic comparison.
- Alembic migrations, audit logs, refresh tokens, and shadcn/ui components.
- PDF export.

## Quick start (development)

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check .
```

Environment variables used by the API and worker: `MALVAX_DATABASE_URL`, `MALVAX_REDIS_URL`, `MALVAX_STORAGE_DIR`, `MALVAX_JWT_SECRET`, `MALVAX_CORS_ORIGINS`. Secrets must come from the environment, never from the code.

## Layout

```
malvax/          core library: intake, ELF, strings, YARA, monitors, correlation, risk, report, API, worker
frontend/        Next.js interface
rules/           YARA rules (laboratory rules only)
experiments/     static evaluation harness and results
deploy/          Prometheus and Grafana configuration
tests/           pytest suite
docs/            architecture, threat model, sandbox security, limitations
```

## License

MIT. See [LICENSE](LICENSE).
