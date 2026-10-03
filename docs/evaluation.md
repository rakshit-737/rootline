# Evaluation

Every number on this page is rendered from committed JSON by `scripts/render_tables.py`
(the tables below are `results/TABLES.md`; each table names its source file and the run that
wrote it). How to regenerate each file is on [Reproduce](reproduce.md). The short version of
the findings:

- **Reconstruction (ATLAS).** On the four scenarios the traversal was designed on, the full
  method beats naive reachability on every log (event F1 0.66 vs 0.25; ΔF1 +0.41, t(3) 95 % CI
  [0.24, 0.58]). On the 12 **held-out** M1-M6 host logs it is 2.4x more precise (0.62 vs 0.26),
  but recall drops to 0.72 and the F1 gain is not significant (higher on 9 of 12 logs, sign-flip
  p = 0.28). **Session-root stops** are the component that transfers: precision is higher on
  12 of 12 held-out logs (+0.10 [0.07, 0.14], exact sign test p = 0.0005) with recall
  essentially unchanged (-0.0045 [-0.012, -0.0003]). The held-out logs are unseen host logs from
  the same testbed, and 8 of 12 replay an S1-S4 exploit; on the four logs with a new exploit
  (M2, M4) the stops add +0.12 precision, higher on 4 of 4.
- **Comparison with the paper.** ROOTLINE's naive reachability lands where ATLAS's own
  published graph-traversal baseline does (P 0.15-0.26 vs 0.18). Our PyTorch reproduction
  of the ATLAS LSTM does **not** reach the published entity-level numbers, nor ATLAS's own
  cleaned list scored the same way (0.86-1.00); ATLAS's shipped raw model output does not
  either.
- **Rules.** v0.3 detects 23/27 in-sample `dev2` captures but **4/64** parsed sealed
  captures (Wilson [0.02, 0.15]). The rules do not generalise; 96 of 160 sealed captures are
  not even parsed.
- **Unsupervised ranking.** IsolationForest does not outperform a one-line "user-dir image
  first" heuristic on the held-out hosts (recall@10 0.78 vs 0.93; the heuristic is higher on 8,
  lower on 1 and tied on 3 of 12 logs, sign test p = 0.039) and falls to 0.49 without that
  single feature.
- **Live kernel.** The probe recovers the scripted chain on a real kernel in CI in one query,
  with the download socket as a root cause, in 72 of 72 completed jobs over 15 pushes (71 of
  72 jobs pass every check; one row per job in `results/live_ebpf.json`).

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

**Statistics.** Means are means of per-log means, and the log is the unit of every test,
because pivots in one log share a graph and are not independent. For the 12 held-out logs,
intervals are 95 % percentile intervals from a log-cluster bootstrap (2,000 resamples), and
paired differences against `naive` get exact two-sided sign and sign-flip tests over logs; the
smallest attainable p with 12 logs is 2/2^12 = 0.00049. For the four S logs, a bootstrap
cannot extend past the extreme logs and no distribution-free test can go below p = 0.125, so
the tables give the range over the four logs and a t(3) interval for the difference. Pivot
counts are reported as description only. p-values are stored to 4 significant digits and never
printed as 0. Rule coverage uses Wilson intervals computed from the counts. IsolationForest's
per-log value is the mean over 10 seeds.

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

![Ablation: one dot per log](img/results/ablation.png)

![Session-root stops per held-out log](img/results/ablation_stops.png)

--8<-- "results/TABLES.md"

## Reading the comparison with published work

- **Event universe.** ROOTLINE scores 63-73 % of the lines ATLAS labels as attack (table
  above): browser rows, pid-less rows and audit lines that carry no file or network
  operation have no syscall-level event. A recall measured against all `+` lines would be
  lower by that factor. ATLAS's own attack-event counts (Table 3) equal the `+` line counts
  for 9 of the 10 attacks; for M-3 the `+` lines number 35,186 against Table 3's 34,979.
- **Starting entity.** The paper's Table 4 starts S-1, S-3, M-5 and M-6 from a malicious
  host, S-2, S-4, M-1 and M-2 from a leaked file, and M-3 and M-4 from a malicious file.
  ROOTLINE's IOC runs start from the attacker address, and the ablation uses every entity.
- **Same campaigns.** The paper's Table 2 builds S-1/M-1, S-2/M-3, S-3/M-6 and S-4/M-5 from
  the same APT reports and exploits; only M-2 (CVE-2015-5119) and M-4 (CVE-2018-8174) are
  new. The ablation therefore reports the M2/M4 logs separately.
- **Training.** ATLAS trains leave-one-attack-out on labelled sequences; ROOTLINE uses no
  labels. ATLAS's released `evaluate.py` scores a manually entered cleaned entity list (the
  script stops until one is filled in); the shipped `eval_*.json` files contain such a list,
  and for S1 it equals the ground truth exactly. Scored without that list, ATLAS's own raw
  model output gives entity F1 0.71 / 0.70 / 0.39 / 0.33 on S1-S4.
- **Entity universe.** Our scorer counts ROOTLINE's abstracted entities (652 for S1, 11 of them
  malicious), the paper's Table 4 counts 7,467 (22 malicious). The like-for-like reference for
  our reproduction is therefore ATLAS's own cleaned list under our scorer (F1 0.86-1.00), not
  the paper's 0.89-1.00.
- **Our LSTM reproduction** (`repro/atlas_repro.py`, PyTorch, 5 seeds, run in the manual
  `atlas-repro` workflow) follows ATLAS's released code (batch 1 and 8 epochs as in its
  `atlas.py`, sequence length 400). Mean entity F1 per scenario is 0.30-0.65 with a regenerated
  training set and 0.24-0.75 with ATLAS's shipped training set; the 5-seed ranges are in the
  table above. Differences
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
removes 3.8-4.35x of the edges on S1-S4 and 3.8-5.81x across all 16 logs; vertex counts do not change.

## Raw tables

The full per-scenario tables (including IsolationForest ranking and the per-capture coverage
rows) are on [Raw benchmark tables](benchmarks.md).
