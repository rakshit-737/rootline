# ROOTLINE

**Provenance-graph attack reconstruction.** ROOTLINE turns host telemetry (Sysmon,
auditd/AUOMS, ATLAS audit logs, or its own bpftrace probe) into an append-only,
hash-chained provenance graph and reconstructs the attack story from one alert or IOC:
**root cause, causal spine and blast radius**, with every step explainable as graph edges.

!!! abstract "Contribution"
    An open, training-free, time-respecting provenance reconstructor whose components are
    ablated on ATLAS with **held-out** hosts and whose sensor-to-story path is exercised on a
    **live kernel in CI**: on 12 held-out ATLAS host logs, session-root stops alone raise event
    precision from 0.26 to 0.36 at unchanged recall (33 of 34 pivots), and the full method
    reaches 0.63 precision at 0.72 recall. On the four scenarios it was designed on it reaches
    F1 0.66 versus 0.25 for plain reachability. It does not match ATLAS's supervised
    model, and its rule tagger does not generalise (4 of 64 sealed captures detected).

[Open the replay UI](demo/){ .md-button .md-button--primary }
[Try it in 60 seconds](getting-started.md#try-it-in-60-seconds){ .md-button }
[Evaluation](evaluation.md){ .md-button }

![Attack-replay UI on the OTRF Log4Shell capture](img/replay-ui.png)

## Try it in 60 seconds

```bash
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/rootline:latest   # then open http://127.0.0.1:8000
```

or `pip install -e .` in a clone and
`rootline analyze tests/fixtures/log4shell_sysmon.json tests/fixtures/log4shell_auoms.json`
(expected output on [Getting started](getting-started.md)).

## Headline results

| Result | Number | Source |
|---|---|---|
| ATLAS S1-S4 (design data), full vs naive reachability | event F1 0.66 [0.51, 0.78] vs 0.25 | `results/ablation.json` |
| ATLAS M1-M6 hosts (held out), full vs naive | precision 0.63 vs 0.26, recall 0.72 vs 0.98, F1 0.46 vs 0.33 (gain not significant) | `results/ablation.json` |
| Session-root stops alone, held out | precision +0.10 [0.07, 0.14], 33 of 34 pivots | `results/ablation.json` |
| ATLAS paper's own traversal baseline vs ROOTLINE naive | P 0.18 vs 0.15-0.26 | paper Table 5, `results/ablation.json` |
| ATLAS LSTM, our reproduction (entity F1) | 0.24-0.75 vs paper 0.89-1.00: **not reproduced** | `results/atlas_repro.json` |
| Rules v0.3: in-sample dev2 vs sealed | 23/27 vs **4/64** detected | `results/coverage.json` |
| Live bpftrace probe in CI | 41/42 jobs pass over 9 pushes; chain recovered in one query in all 42 | `results/live_ebpf.json` |
| Graph reduction (16 ATLAS logs) | 3.8-5.8x fewer edges, lossless by design | `results/atlas.json` |

## Pages

- [How it works](how-it-works.md): one live capture from kernel events to the story.
- [Evaluation](evaluation.md): methodology, all results with CIs, the published comparison.
- [Reproduce](reproduce.md): exact commands, runtimes and where each number was computed.
- [Rule-evaluation protocol](protocol.md), [Limitations](limitations.md), [ADRs](adr/0001-process-image-vertices.md).

!!! warning "Lab use only"
    ROOTLINE analyses captured telemetry. It contains no exploit or malware code; the datasets
    are event logs downloaded outside the repository, and the live CI chain uses dummy files
    and traffic that never leaves the runner.
