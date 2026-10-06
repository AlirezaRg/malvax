# Threat Model

## Assets

| Asset | Why it matters |
|---|---|
| Host OS and host files | Compromise through a sample escape would expose the analyst's machine |
| Analysis VM | Runs untrusted code; must be reverted after every run |
| Samples | Confidential lab material; must not leak to third parties |
| Database | Holds findings, reports and audit trail |
| Reports | May contain sample strings and indicators; treat as sensitive |
| User accounts / API | Access to submission and analysis |
| AI module | Reads sample-derived text; must not gain tool access |

## Threats and mitigations (status in brackets)

| Threat | Mitigation | Status |
|---|---|---|
| Malicious sample escapes VM | Dedicated VM, snapshot revert, no shared folders, unprivileged runner, no host credentials | Design only (Phase 4) |
| Host compromise via controller | Controller never executes samples; parses telemetry as untrusted; no `shell=True` anywhere | Enforced in Phase 1 code by convention, tests for sanitization |
| Resource exhaustion | rlimits, wall-clock timeout, output-size cap, max process count | Phase 4 |
| Malicious input (filename, ELF metadata) | Filename sanitization; magic-byte identification without external tools; size limit | **Implemented (Phase 1)** |
| Prompt injection via strings / logs | AI receives structured evidence only; sample text is labeled untrusted | Phase 15 |
| Data exfiltration from the sandbox | OFFLINE default; controlled network allow-list; no default route | Phase 7 |
| Unauthorized analysis | Authentication, RBAC (Viewer/Analyst/Admin), audit log | Phase 14 |
| Privilege escalation in the app | Least-privilege DB role; admin-only config and retention | Phase 14 |
| Upload-time execution | Intake never runs the file; only reads bytes | **Implemented (Phase 1)** |
| Hash collision / duplicate confusion | SHA-256 is the primary key; MD5/SHA-1 are informational | **Implemented (Phase 1)** |
| Path traversal via upload name | `os.path.basename` + character whitelist; name never used as a path | **Implemented, tested** |

## Accepted residual risks

- No software sandbox guarantees perfect isolation. Hypervisor bugs and guest-to-host
  escapes are outside MalvaX's control. Mitigation is defence in depth plus a disposable VM.
- Hashes identify files, not intent. Two different samples cannot share SHA-256 in practice,
  but MD5 and SHA-1 collisions are known, so they are never used as identifiers.
