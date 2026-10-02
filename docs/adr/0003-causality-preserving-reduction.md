# ADR 0003: Causality-preserving edge merge and benign-leaf pruning

- Status: accepted (v0.1)

## Context

The spec asks how far provenance can shrink while keeping 100% of the
attack-relevant paths. The full-strength published systems are heavy: CPR
(Xu et al., CCS'16), NodeMerge (CCS'18), LogGC (CCS'13). A teachable subset has
to be correct first and small second.

## Decision

- **Edge merge (CPR rule).** Repeated `(src, dst, rel)` edges fold into one edge
  with `count` and `last_ts`, *unless* the source received new input since the
  previous occurrence. In that case the new edge could carry different
  information, so it is kept.
- **Benign-leaf pruning.** Read-only files that nothing wrote during the capture
  and that match a loader-noise allowlist (shared libraries, locale, `/proc`, the
  ld cache) are dropped. `ld.so.preload` is deliberately *not* on the list,
  because it is a rootkit vector. Vertices that raised alerts are pinned.
- Reduction runs **after** tagging, so rules see the full graph.

## Consequences

- ATLAS S1-S4: a 3.8-4.4x edge reduction. Preserving 100 % of the distinct
  attack-labelled `(src, dst, rel)` keys follows from the design (the first edge
  of every key is kept), so it is a property, not a measurement. The empirical
  check is that reconstruction on the reduced graph returns the same story as on
  the raw graph (`rootline-noreduce` row). It is not reliably faster, because the
  timed block includes the reduction itself.
- The allowlist is Linux-centric. Windows DLL loads are merged but not pruned,
  which is conservative.
- NodeMerge-style template merging of whole subgraphs is not implemented.
