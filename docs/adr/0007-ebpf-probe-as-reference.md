# ADR 0007: The eBPF probe stays a documented reference; evaluation uses recorded telemetry

- Status: **superseded** by [ADR 0008](0008-live-ebpf-in-ci.md) (v1.1). The probe now runs live in CI.

## Context

The spec's sensor is eBPF (libbpf, BCC or bpftrace). It needs a recent Linux
kernel and root. The development machine is Windows, and CI runners cannot load
BPF programs without privileged containers. The spec itself grades live probes
C/D and says "don't rebuild the sensor; build the graph brain".

## Decision

- `probes/rootline.bt` stays a readable bpftrace reference. It emits exactly the
  `k=v` lines `normalize.parse_bpftrace_line` reads, and its tracepoints
  (`sched_process_fork`, `sys_enter_execve`, `openat`, `connect`, `unlinkat`,
  `exit`) map one-to-one onto ROOTLINE event kinds. CI does not run it.
- Real-data evaluation uses *recorded* host telemetry from the same syscall
  family: Sysmon for Linux (itself eBPF-based via SysinternalsEBPF), auditd/AUOMS
  and ATLAS' audit logs. The engine is sensor-agnostic by construction (ADR 0006).

## Consequences

- There is no claim of in-kernel tamper resistance measured on a live host. The
  "anti-forensics" demo shows that log deletion is itself recorded and that the
  SHA-256 hash chain exposes edits to the stored record.
- Roadmap: a libbpf CO-RE ring-buffer port with fd-to-path resolution for
  `write()`, IPv6 and self-PID filtering, exercised in a privileged Linux CI job.
