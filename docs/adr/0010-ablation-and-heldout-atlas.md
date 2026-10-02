# ADR 0010: Ablate the reconstructor, and hold out the ATLAS multi-host logs

- Status: accepted (v1.1). Extends the ATLAS part of [ADR 0004](0004-evaluation-protocol.md).

## Context

v1.0 reported ROOTLINE against naive reachability on ATLAS S1-S4 from one starting IOC per
scenario. Two problems: the v0.2 traversal heuristics (Windows session-root stops, the
browser-profile penalty) were written while looking at S1-S4, so the comparison was
in-sample; and one pivot per scenario cannot say which component helps, or how much the
result depends on where the analyst starts.

## Decision

- `reconstruct()` gets four switches, each turning one component off: `timed`
  (time-respecting traversal), `stops` (session-root stops), `spine` (keep only the causal
  spine of the backward slice) and `accessed` (add what intrusion-created processes read
  and the images they ran). Defaults are unchanged.
- `rootline.ablation` runs seven variants from **every** ground-truth entity that maps to a
  vertex, plus ATLAS's own starting IOC (the paper's random-symptom protocol).
- Scenarios are split into **S1-S4** (design data, in-sample) and the **12 per-host logs of
  M1-M6** (never used for design, held out). The merged `*_multi` logs are skipped because
  they have no single host address.
- Uncertainty: pivots within a scenario are correlated, so intervals come from a
  scenario-cluster bootstrap (2,000 resamples); paired differences against `naive` also get
  an exact sign test over pivots.

## Consequences

- On S1-S4 the full method is clearly better than naive reachability (F1 0.66 vs 0.25).
- On the held-out hosts the picture is mixed and is reported as such: the full method's
  precision gain holds (0.63 vs 0.26) but recall falls to 0.72 and the F1 gain
  (+0.14, 95 % CI [-0.11, 0.35]) is not significant. Session-root stops alone are the
  component that transfers cleanly (precision +0.10 on 33 of 34 pivots, recall unchanged).
  Spine trimming without the `accessed` expansion collapses recall (about 0.06-0.23), so
  the two only work together.
- Root-cause hit@3 (any top-3 entry point is a ground-truth entity) is about 0.45-0.48 for
  every variant: ranking entry points is the weakest part of the reconstructor.
