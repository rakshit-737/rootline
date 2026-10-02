# ADR 0002: Time-respecting traversal, session-root stops, causal spine

- Status: accepted (v0.1), extended (v0.2)

## Context

Plain graph reachability on host provenance "explodes": within a few hops,
everything depends on everything. On ATLAS S1 the naive backward-plus-forward
closure from the attacker IP holds 4,735 vertices and 75% of all events.

## Decision

1. **Time-respecting** (King & Chen, SOSP'03). Walking backward from a vertex at
   time *t* follows only in-edges at or before *t*, and then continues from the
   predecessor with bound `min(t, edge.end_ts)`. Forward traversal is the mirror
   image. A Dijkstra-style heap keeps the tightest bound for each vertex.
2. **Session-root stops.** Backward expansion does not continue past session and
   service roots (`systemd`, `sshd`, `cron`; on Windows `services.exe`,
   `explorer.exe`, `svchost.exe` and similar). These are where a session starts,
   not why an attack happened. *v0.2:* forward expansion also stops at them.
   An indexer or crash reporter that touched `payload.exe` must not pull its whole
   lifetime into the blast radius.
3. **Causal spine.** After ranking entry points (a file or socket that fed the
   slice *strictly before* the pivot time), backward vertices that no entry point
   can reach are dropped.
4. **Accessed set.** Reads made after the pivot by processes that the intrusion
   *created* are added (this is how credential access shows up). *v0.2:*
   long-lived processes that were only tainted, such as a browser, are excluded.
   Otherwise their whole cache becomes "accessed".
5. **Multi-seed IOC pivots** (v0.2). An attacker IP maps to several socket
   vertices. Each one is traced backward from its last contact and forward from
   its first contact.

## Consequences

- On ATLAS S1-S4 (in-sample) the full reconstructor is about 3.5x more precise than
  naive reachability at similar recall. On held-out M1-M6 hosts it is 2.4x more
  precise but loses recall (0.72); time-respecting traversal alone adds +0.05
  precision there. See [ADR 0010](0010-ablation-and-heldout-atlas.md) and `results/ablation.json`.
- Coarse process-level provenance cannot split a long-lived browser's unrelated
  work from the exploit. This is the remaining precision loss. Execution
  partitioning (BEEP/MPI-style units) is on the roadmap.
- Every step can be explained as an edge with a timestamp. No learned model
  decides what belongs in the story.
