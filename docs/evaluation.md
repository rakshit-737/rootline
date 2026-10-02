# Evaluation

Every number on this page is rendered from committed JSON by `scripts/render_tables.py`
(the tables below are `results/TABLES.md`). How to regenerate each file is on
[Reproduce](reproduce.md). The short version of the findings:

- **Reconstruction (ATLAS).** On the four scenarios the traversal was designed on, the full
  method beats naive reachability clearly (event F1 0.66 vs 0.25). On the 12 **held-out**
  M1-M6 host logs, it is 2.4x more precise (0.63 vs 0.26) but recall drops to 0.72, and the
  F1 gain is not significant. **Session-root stops** are the component that transfers:
  +0.10 precision on 33 of 34 held-out pivots at unchanged recall.
- **Comparison with the paper.** ROOTLINE's naive reachability lands where ATLAS's own
  published graph-traversal baseline does (P 0.15-0.26 vs 0.18). Our PyTorch reproduction
  of the ATLAS LSTM does **not** reach the published entity-level numbers; ATLAS's own
  shipped raw model output does not either.
- **Rules.** v0.3 detects 23/27 in-sample `dev2` captures but **4/64** parsed sealed
  captures. The rules do not generalise; 96 of 160 sealed captures are not even parsed.
- **Live kernel.** The probe recovers the scripted chain on a real kernel in CI in one
  query, with the download socket as a root cause.

## Methodology

**Data.** ATLAS (Alsaheel et al., USENIX Security 2021) ships pre-processed Windows audit,
DNS and browser logs where every line is labelled `+` when it involves a ground-truth
attack entity. ROOTLINE uses the audit and DNS rows (browser rows have no pid); a raw event
is an **attack event** when its line is `+`. Events are **predicted** when both endpoints
of their provenance edge are in the story. DNS events are not scored.

**Pivots.** One run per (log, pivot): ATLAS's own starting IOC (`user_artifact.txt`)
and every ground-truth entity that maps to a vertex (the paper's random-symptom protocol).
**Entity recall** counts ground-truth entities found other than the ones the pivot itself
covers. **Root-cause hit@3** asks whether any of the three top-ranked entry points is a
ground-truth entity.

**Design vs held-out data.** The v0.2 traversal heuristics (Windows session roots, the
browser-profile penalty, the `user-dir` anomaly feature) were written while looking at
S1-S4, so S1-S4 results are in-sample. The per-host logs of M1-M6 were never used for
design. See [ADR 0010](adr/0010-ablation-and-heldout-atlas.md).

**Statistics.** Means are means of per-log means. Intervals are 95 % percentile intervals
from a scenario-cluster bootstrap (2,000 resamples), because pivots in one log are not
independent. Paired differences against `naive` also get an exact two-sided sign test over
pivots. Rule coverage uses Wilson intervals. IsolationForest intervals (raw tables) cover
only seed variance on fixed data.

**Variants.** Each switches components of the same reconstructor off:

| variant | time-respecting | session-root stops | causal spine | accessed expansion |
|---|---|---|---|---|
| naive | | | | |
| naive+stops | | yes | | |
| time | yes | | | |
| time+stops | yes | yes | | |
| time+spine | yes | | yes | |
| time+stops+spine | yes | yes | yes | |
| full (ROOTLINE) | yes | yes | yes | yes |

![Ablation](img/results/ablation.png)

--8<-- "results/TABLES.md"

## Reading the comparison with published work

- **Event universe.** ROOTLINE scores 63-73 % of the lines ATLAS labels as attack (table
  above): browser rows, pid-less rows and audit lines that carry no file or network
  operation have no syscall-level event. A recall measured against all `+` lines would be
  lower by that factor. ATLAS's own event counts (Table 3) equal the `+` line counts.
- **Starting entity.** The paper starts S-2 and S-4 from a leaked file; ROOTLINE's IOC runs
  start from the attacker address, and the ablation uses every entity.
- **Training.** ATLAS trains leave-one-attack-out on labelled sequences; ROOTLINE uses no
  labels. ATLAS's published event-level numbers are derived from its entity predictions
  after a manual step: the shipped `eval_*.json` files contain a hand-"cleaned" entity list
  (for S1 it equals the ground truth exactly). Scored without that list, ATLAS's own raw
  model output gives entity F1 0.71 / 0.70 / 0.39 / 0.33 on S1-S4.
- **Our LSTM reproduction** (`repro/atlas_repro.py`, PyTorch, batch 1, 8 epochs, maxlen 400,
  5 seeds, run in the manual `atlas-repro` workflow) reaches entity F1 0.30-0.65 with a
  regenerated training set and 0.24-0.75 with ATLAS's shipped training set. Differences
  that may explain the gap: Keras vs PyTorch initialisation, rapidfuzz vs fuzzywuzzy in
  undersampling, and the manual cleaning step. The paper's numbers are **not reproduced**.
- **Graph-traversal baseline.** The paper's Table 5 traversal baseline (P 0.18, R 1.00) and
  ROOTLINE's naive reachability (P 0.15 on S1-S4, 0.26 on M hosts) agree, which is a useful
  check that the event universes are comparable at least for traversal methods.

## Reduction

The reduction is lossless for causality by construction: it merges repeated edges only when
no new information reached the source in between, and keeps the first edge of every
(source, target, relation) key. "100 % of attack edges preserved" is therefore a property of
the design, not an empirical finding. The empirical check is that stories with and without
reduction are identical (`rootline` vs `rootline-noreduce` in the raw tables). On ATLAS it
removes 3.8-4.4x of the edges on S1-S4 and 3.8-5.8x across all 16 logs; vertex counts do not change.

## Raw tables

The full per-scenario tables (including IsolationForest ranking and the per-capture coverage
rows) are on [Raw benchmark tables](benchmarks.md).
