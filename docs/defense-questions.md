# Defense preparation

Short, technically accurate answers. Each one points to the code or document that backs it.

## Linux
1. **What is an ELF file?** A binary format: a header, program headers (what the loader maps) and section headers (what the linker and tools use). `malvax/elf.py` parses both.
2. **What is the difference between program headers and sections?** Program headers describe segments the loader maps at run time. Sections describe the file for linkers and inspection tools. The loader ignores sections.
3. **What does PIE mean?** Position-independent executable: the load address is randomized (ASLR). Reported only for ET_DYN files with an interpreter.
4. **What is NX (non-executable stack)?** `PT_GNU_STACK` without the execute flag. Its absence is reported as "unknown", not as a vulnerability.
5. **What is RELRO?** Relocation read-only. "Full" also sets BIND_NOW so the GOT is read-only after loading.
6. **What is a stack canary?** A value checked before return. We detect it by the presence of `__stack_chk_fail`, which proves nothing about how it is used.
7. **How does `/proc` expose processes?** `/proc/<pid>/stat` (state, parent PID, start time), `status` (UID/GID), `cmdline`, and `fd/` symlinks. `process_monitor.py` reads these.
8. **How are sockets attributed to a process?** `/proc/net/tcp` lists socket inodes. `/proc/<pid>/fd` links show `socket:[inode]`. Matching the two gives the owner.
9. **What is a system call?** The controlled interface from user space to the kernel. `strace` observes them via ptrace.
10. **Why are permissions relevant?** A sample running as an unprivileged account cannot modify system files. That is why the guest account has no sudo.

## Malware analysis
11. **Static versus dynamic analysis?** Static reads the file without running it. Dynamic runs it in a controlled environment and observes behavior.
12. **What is a behavioral indicator?** An observed event such as process creation or a connection. It is evidence, not a verdict.
13. **What is a false positive?** A benign sample flagged as suspicious. Our synthetic set has none, but that is not a measured rate.
14. **What is a false negative?** A sample with behavior that is not flagged. The static evaluation found one, which led to a documented change of criterion.
15. **Why not use a single malicious/benign label?** A binary label hides why the decision was made and cannot express uncertainty. Scores with reasons are auditable.
16. **Why do we report "NOT_MEASURED"?** A number that was not measured is a fabrication. The honest value is absence.
17. **What does YARA do?** Pattern matching on bytes and strings with rule metadata. We use it for laboratory rules only.

## Sandbox
18. **Why a VM instead of a container?** Containers share the host kernel, so a kernel exploit reaches the host. A VM has its own kernel behind a hypervisor.
19. **Why not run the sample on the host?** One malicious sample could compromise the analyst's machine and data.
20. **What is a snapshot and why revert it?** A saved VM state. Reverting before each run makes each result independent of the previous one.
21. **Why does cleanup run in `finally`?** Cleanup must happen after a failure, a timeout or an exception. Otherwise the next sample inherits a dirty state.
22. **What does the host-only network do?** The guest can reach the host and other VMs on that network, not the Internet. It is not packet-level isolation.
23. **Is the sandbox escape-proof?** No. A hypervisor or kernel vulnerability would break it. This is stated in `docs/sandbox-security.md`.
24. **Why is the guest account unprivileged?** So that a sample that escapes the process still has limited rights inside the guest.
25. **Why use `ulimit`?** It limits CPU, processes, memory and file size of the sample. It is a soft control: a determined sample can try to raise it.

## Programming
26. **Why Python?** Readable, standard library covers parsing and process control, and it is the language of the analysis tooling.
27. **Why FastAPI?** Typed request models, automatic OpenAPI documentation, and good async support.
28. **Why SQLAlchemy?** One schema definition for PostgreSQL in production and SQLite in tests.
29. **Why PostgreSQL?** Concurrent writes from API and worker, and a mature migration story.
30. **Why Redis?** A simple, fast queue. The API only enqueues an ID; the worker does the work.
31. **Why not run analysis inside the HTTP request?** Analysis can take seconds to minutes. Blocking the request would tie up the server.
32. **What is `dequeue` with a timeout?** A blocking pop with a deadline, so the worker can check for shutdown.

## Security
33. **Threat model?** Assets, threats and mitigations are in `docs/threat-model.md`.
34. **Privilege separation?** The API, the worker and the guest account have separate roles. Each runs with only what it needs.
35. **What is untrusted input here?** The sample, its filename, its strings, its ELF metadata and the telemetry it produces.
36. **How is command injection avoided?** Every subprocess uses an argument list. The remote guest command is built with `shlex.join`, and the sample path is derived from a verified SHA-256.
37. **How is resource exhaustion limited?** Upload size, sample timeout, `ulimit`, output size, and the collector's fixed poll interval.
38. **How are passwords stored?** Argon2id hashes only. Plaintext is never stored or logged.
39. **Why JWT?** Stateless sessions. The trade-off: a role change takes effect when the token expires (60 minutes).
40. **Why httpOnly cookies in the frontend?** Scripts on the page cannot read the token, which limits damage from an XSS bug.
41. **What is an SSRF or path-traversal risk here?** The upload filename is reduced to a safe basename, and no path is built from it.

## AI
42. **What does the AI component do?** It writes a summary of structured evidence only. It is off unless configured, and the default is an offline deterministic summary.
43. **Hallucination?** The model can invent facts. Every output is validated: unknown evidence IDs and extra fields are rejected.
44. **Prompt injection?** A sample can contain text such as "ignore previous instructions". Raw sample text never reaches the model; only identifiers, counts and scores do. A test checks this.
45. **Why not let the AI decide the verdict?** A language model cannot be audited and gives no reproducible reason. The verdict stays with the transparent scoring.
46. **AI limitations?** It cannot observe anything itself. It only rephrases evidence it was given.

## Research
47. **Methodology?** Synthetic static set with author labels; three benign dynamic samples run three times each on one VM.
48. **Metrics?** Execution success, observations per run, wall time per run. Detection rates are not reported because there were not enough labeled samples.
49. **Limitations?** See `docs/limitations.md`.
50. **Future work?** Connect strace (needs root in the guest), add more behavior samples, measure combined static and dynamic detection, and add PDF reports and migrations.
51. **Why are results not statistically significant?** Three samples and three repetitions cannot support a rate or a confidence interval.
52. **How could another researcher reproduce this?** `docs/sandbox-setup.md` lists the environment, configuration and commands. The raw telemetry is in the repository.
