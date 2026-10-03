# ROOTLINE

**Provenance-graph attack reconstruction.** ROOTLINE turns host telemetry (Sysmon,
auditd/AUOMS, ATLAS audit logs, or its own bpftrace probe) into an append-only,
hash-chained provenance graph and reconstructs the attack story from one alert or IOC:
**root cause, causal spine and blast radius**, with every step explainable as graph edges.

!!! abstract "Contribution"
    ROOTLINE is a training-free, explainable provenance reconstructor whose session-root stops
    raise event precision on held-out ATLAS host logs by +0.10 [0.07, 0.14] (higher on 12 of 12
    logs) at essentially unchanged recall, with the full sensor-to-story path exercised on a live
    kernel in CI.

It does not match ATLAS's supervised model, and its rule tagger does not generalise (4 of 64
sealed captures detected); both are measured on the [Evaluation](evaluation.md) page.

[Open the replay UI](demo/){ .md-button .md-button--primary }
[Try it in 60 seconds](getting-started.md#try-it-in-60-seconds){ .md-button }
[Evaluation](evaluation.md){ .md-button }

![Attack-replay UI on the OTRF Log4Shell capture](img/replay-ui.png)

## Try it in 60 seconds

```bash
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/rootline-provenance-forensics:latest   # then open http://127.0.0.1:8000
```

or `pip install -e .` in a clone and
`rootline analyze tests/fixtures/log4shell_sysmon.json tests/fixtures/log4shell_auoms.json`
(expected output on [Getting started](getting-started.md)).

## Headline results

Rendered from the committed JSON by `scripts/render_tables.py`; each row names its source file in `results/` and the run that wrote it. Intervals are 95 % (log-cluster bootstrap for the held-out logs, Wilson for counts). "Held out" means unseen host logs from the same ATLAS testbed.

| Result | Number | Source (`results/`) |
|---|---|---|
| ATLAS S1-S4 (design data): full method vs naive reachability, event F1 | **0.66** vs 0.25, higher on 4 of 4 logs (per-log 0.42-0.78 vs 0.15-0.39; ΔF1 +0.41, t(3) 95 % CI [+0.24, +0.58]) | `ablation.json`, bench run 37092501921 |
| ATLAS M1-M6 host logs (**held out**): precision / recall / F1, full vs naive | 0.62 / 0.72 / 0.46 vs 0.26 / 0.98 / 0.33; F1 higher on 9 of 12 logs, ΔF1 +0.14 [-0.11, +0.35] (sign-flip p = 0.28, not significant) | `ablation.json`, bench run 37092501921 |
| Session-root stops alone, held out | precision **+0.10** [+0.07, +0.14], higher on 12 of 12 logs (exact sign test p = 0.00049); recall -0.0045 [-0.0119, -0.0003] | `ablation.json`, bench run 37092501921 |
| Same, only the 4 held-out logs whose exploit is not in S1-S4 (M2, M4) | precision +0.12, higher on 4 of 4 logs (descriptive) | `ablation.json`, bench run 37092501921 |
| ATLAS paper's graph-traversal baseline vs ROOTLINE naive reachability, event precision | 0.18 vs 0.15 / 0.26: consistent | paper Table 5; `ablation.json`, bench run 37092501921 |
| ATLAS LSTM, our reproduction (entity F1, S1-S4, mean of 5 seeds) | 0.24-0.75 vs ATLAS's cleaned list under our scorer 0.86-1.00 (paper 0.89-1.00): **not reproduced** | `atlas_repro.json`, atlas-repro run 36997669262 |
| Rule tagger v0.3: in-sample dev2 vs sealed, captures detected | 23/27 [0.68, 0.94] vs **4/64 [0.02, 0.15]** | `coverage.json`, sealed-coverage run 36994398382 |
| Live bpftrace probe on a GitHub-hosted kernel | 71/72 CI jobs pass over 15 pushes [0.925, 0.998]; chain recovered in **one query** in 72/72 [0.95, 1.00] | `live_ebpf.json`, ci runs 36996901332..37003827535 |
| Graph reduction (16 ATLAS logs) | 3.8-5.8x fewer edges, lossless by design | `atlas.json`, bench run 37092501921 |

## Pages

- [How it works](how-it-works.md): one live capture from kernel events to the story.
- [Evaluation](evaluation.md): methodology, all results with CIs, the published comparison.
- [Reproduce](reproduce.md): exact commands, runtimes and where each number was computed.
- [Rule-evaluation protocol](protocol.md), [Limitations](limitations.md), [ADRs](adr/0001-process-image-vertices.md).

!!! warning "Lab use only"
    ROOTLINE analyses captured telemetry. It contains no exploit or malware code; the datasets
    are event logs downloaded outside the repository, and the live CI chain uses dummy files
    and traffic that never leaves the runner.
