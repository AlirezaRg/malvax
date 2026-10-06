# Limitations

Read this before drawing any conclusion from MalvaX output.

## Scope
- MalvaX analyzes **Linux ELF executables and simple scripts** in a laboratory. It is not an antivirus
  and not an EDR. It makes no claim about malware families.
- **Kernel-level malware is out of scope.** A rootkit that hides processes, files or sockets from
  `/proc` is not visible to this approach.
- **Packed or encrypted samples** reduce static visibility (strings and YARA see little).

## Dynamic visibility (what is and is not observed)
- **Processes:** polled from `/proc` every 0.2 s. A child that starts and exits between two polls is
  missed. Each event records its observation time.
- **Filesystem:** a snapshot diff of `/tmp` before and after the run. Writes elsewhere are not seen.
  Files created and deleted within one run are not seen. Timestamps are per run, not per event.
- **Network:** socket state from `/proc/net`, attributed to the sample by PID. This is **socket
  visibility, not packet capture**: no payloads, no DNS queries, no per-packet timing.
  Sockets that exist only briefly between two polls are missed.
- **System calls:** not collected yet. The field is `NOT_COLLECTED`.
- **Anti-analysis:** a sample that detects the VM, sleeps, or waits for input may behave differently.
  Those observations are not evidence that the sample is benign.

## Correlation and scoring
- Timing-based correlation (for example "file written, then connection") is **not applied** to dynamic
  evidence, because filesystem and socket evidence has no per-event time.
- The risk score is a transparent heuristic with fixed weights. The weights are not measured or
  validated. Reported scores are not classifications.

## Evaluation
- The static evaluation uses synthetic samples whose labels were written by the author. Its numbers
  show consistency with the design, not detection performance on real malware.
- Dynamic and combined evaluations are reported with the number of runs performed. Results from a
  few runs of a few benign samples are not statistically meaningful.

## Security boundary
- No software sandbox guarantees perfect isolation. The protections are a dedicated VM, snapshot
  revert, an unprivileged guest account, host-only networking, and resource limits.
- The analysis account can still read and write its own files and use the CPU and memory it is
  given. The limits are enforced by `ulimit`, which is a soft control.
