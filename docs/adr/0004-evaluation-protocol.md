# ADR 0004: Evaluation protocol (ATLAS from the analyst IOC; coverage with a held-out split)

- Status: accepted (v0.2). The **tagging-coverage** part is superseded by [ADR 0009](0009-sealed-rule-protocol.md): the `holdout` split was burned in v1.1 and renamed `dev2`. The ATLAS part is extended by [ADR 0010](0010-ablation-and-heldout-atlas.md).

## Context

The v0.1 numbers came from ROOTLINE's own synthetic generator, and they were
circular. v0.2 needed labelled public data it could evaluate honestly, on a
Windows laptop, with less than about 15 GB of downloads.

## Options considered

| Dataset | Labels | Size | Verdict |
| --- | --- | --- | --- |
| DARPA TC E3/E5 (CDM) | Engagement reports, not per-event labels. Community labels vary | 100s of GB per host | Too large, and the ground truth is disputed. Roadmap only |
| ATLAS (USENIX Sec'21) artefact | Every log line labelled `+`/`-`, plus the malicious entity list and the analyst's starting IOC | 14 MB (S1-S4) | **Chosen** for reconstruction |
| OTRF Security-Datasets | One compound Linux attack (Log4Shell) with Sysmon **and** AUOMS | < 1 MB | **Chosen** for a real Linux case study and fusion |
| Splunk attack_data (Sysmon for Linux) | One ATT&CK technique per capture | ~0.3 GB | **Chosen** for tagger coverage |

## Decision

**Reconstruction (ATLAS S1-S4).** Start from `user_artifact.txt`, the attacker IP
that ATLAS gives its own investigator. Every method gets the same pivot and the
same graph:

- `ioc-grep`: the IOC vertices plus their 1-hop neighbours. This is what a SIEM
  search returns.
- `naive-bfs`: backward and forward reachability with no time and no stops.
- `rootline-noreduce` / `rootline`: this engine without and with reduction.

Scoring is at **event level**. An event is predicted when both endpoints of its
edge are story vertices, and it is true when ATLAS labels its line `+`. Entity
recall is also reported against `malicious_labels.txt`. Web-object entities
(`index.html`) are excluded because a syscall engine cannot see them.

**Tagging coverage.** A capture counts as detected when at least one alert fires.
A stricter column also requires the alert's ATT&CK technique to match the folder
technique. Datasets are split into:

- `dev`: the captures read while the v0.2 command-line rules were written
  (in-sample, optimistic).
- `holdout`: 27 captures listed from the repository afterwards and never opened
  before the first scoring run. *(Superseded: once its misses were published and used to write v0.3, it stopped being a holdout. See ADR 0009.)*

**Anomaly tagging.** IsolationForest over process vertices is unsupervised and fit
per scenario. It is ranked against ATLAS' malicious process images and compared
with degree ranking and the random expectation.

## Consequences

- ATLAS labels are line-level ("involves a malicious entity"). That includes
  benign services that merely *read* `payload.exe`, so perfect precision is
  hard for any causality-based method (the high-recall traversals here stay below
  0.6 precision; seed-plus-one-hop IOC grep reaches ~1.0 precision at ~4 % recall). The numbers are useful for
  *comparing* methods on the same labels. ATLAS publishes event-level results too
  (Table 4) and a graph-traversal baseline (Table 5); the comparison, with the
  differences in event universe and starting entity, is on the Evaluation page.
- The held-out split shows how much the rule set overfits. The gap is
  reported, not hidden.
