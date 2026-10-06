# MalvaX — Linux Malware Analysis and Behavioral Sandbox

MalvaX is a defensive, academic analysis platform. It does **not** create malware. Its job is
to hash, describe, and (in later phases) observe suspicious Linux ELF binaries inside an
isolated laboratory VM.

**Current status: Phase 1 (architecture + sample intake) is implemented and tested.**
Later phases are documented in `docs/architecture.md` and are not yet built.

## Quick start

```bash
cd malvax
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
```

Phase 1 API surface (Python):

```python
from pathlib import Path
from malvax.intake import intake_sample
from malvax.store import SampleStore

meta = intake_sample(Path("suspect.bin"), original_name="suspect.bin")
store = SampleStore("malvax.db")
sample = store.add_sample(meta)  # SHA-256 is the dedup key
```

## Layout

```
malvax/
├── malvax/
│   ├── intake.py      hashing, magic-byte file type, filename sanitization, size limits
│   ├── lifecycle.py   analysis state machine
│   └── store.py       SQLite store for samples and state transitions
├── tests/             pytest suite (unit tests for intake, lifecycle, store)
├── docs/              architecture, threat model, sandbox security, roadmap
├── pyproject.toml     ruff and pytest configuration
└── README.md
```

Planned directories (`analyzer/`, `sandbox/`, `collectors/`, `detection/`, `rules/`,
`lab_samples/`, `lab_network/`, `backend/`, `frontend/`, `deploy/`, `experiments/`) are created
when their phase starts. Empty placeholder folders are not committed.

## Safety

- Phase 1 never executes uploaded files.
- No `shell=True`, no `os.system`. External tools will be called with explicit argument lists.
- Samples are untrusted input at every stage.
- Do not run samples on the host. Use the Phase 4 VM once it exists.

## Limitations

See `docs/architecture.md` §8 and `docs/threat-model.md`. Measured performance and detection
accuracy: **NOT YET MEASURED**.
