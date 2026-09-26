# ADR 0001: One vertex per process image, edges follow information flow

- Status: accepted (v0.1)
- Context: the graph model decides what "backward" and "forward" mean.

## Context

A PID is not an identity. PIDs are reused, and `exec` replaces the program running
under a PID while keeping it. Many provenance systems key processes by PID plus
start time, and treat `exec` as an attribute change. If you do that, a shell that
runs `curl` and then runs `/tmp/.x` becomes one vertex, and everything `/tmp/.x`
does is blamed on the shell's earlier inputs.

## Decision

- Every `fork` and every `exec` creates a new process vertex, `proc:<host>:<pid>:<seq>`.
  An `exec` links the old image to the new one with a `FORKED` edge, and links the
  binary file to the new image with an `EXECUTED` edge.
- Edges point in the direction of **information flow**. Examples: `file -READ-> proc`,
  `proc -WROTE-> file`, `proc -CONNECTED-> socket` and `socket -RECEIVED-> proc`.
  Backward traversal then means "what could have influenced this" with no special
  cases.
- Sockets are keyed by remote `ip:port`. DNS events attach `domains` to them
  (ADR 0006), so an IOC can be either an IP or a domain.

## Consequences

- Exec chains stay readable (`bash[1189] -> .x[1188]`), and PID reuse cannot merge
  two unrelated programs.
- The graph has more process vertices than a PID-keyed model. Reduction (ADR 0003)
  offsets this.
- Loaders must emit a `fork` before an `exec` when the source only reports process
  creation. Sysmon EID 1 and ATLAS first sightings do this.
