# Datasets

Everything is fetched by `python scripts/download_data.py` into `$ROOTLINE_DATA`
(default `~/.cache/rootline`), **outside the repository**, with SHA-256 and size
checks; entries without a pinned hash are refused. URLs are pinned to upstream
commits (ATLAS `e46096d`, Splunk attack_data `b4573ed3`). The default set is
78 files, 736.5 MB. `scripts/data_manifest.json` is the single source of truth.
No dataset contains executable content: they are event logs and pre-processed
audit CSVs. ATLAS model weights (`*.h5`) are skipped on extraction.

| Source | What | Size | Licence | Used for |
| --- | --- | --- | --- | --- |
| [ATLAS artefact](https://github.com/purseclab/ATLAS) `paper_experiments/S1.zip` | 4 single-host Windows attack scenarios (CVE-2015-5122, CVE-2015-3105, CVE-2017-11882, CVE-2017-0199). Line-labelled audit + DNS + Firefox logs | 13.7 MB zip, ~125 MB extracted | Apache-2.0 | Reconstruction, reduction, anomaly benchmarks; ablation (design data) |
| ATLAS `M1.zip` (optional, `--all`) | Per-host logs (h1, h2) of the multi-host scenarios M1-M6 | 62 MB zip, ~700 MB extracted | Apache-2.0 | Ablation and IOC benchmark on **held-out** hosts |
| ATLAS `S2.zip`-`S4.zip` (optional, `--split repro`) | The other experiment folders (training sets, seq-graphs) | 42 MB | Apache-2.0 | LSTM reproduction only |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) Log4Shell compound | Sysmon for Linux + AUOMS from one CVE-2021-44228 exploitation | < 1 MB | MIT | Real Linux case study, sensor fusion |
| OTRF atomic Linux | `sh_arp_cache`, `sh_binary_padding_dd` (raw auditd) | < 5 KB | MIT | Loader tests |
| [Splunk attack_data](https://github.com/splunk/attack_data), `dev` split | 46 Sysmon-for-Linux captures (45 single-technique, 1 malware family; 1 parses to 0 events) | 6.5 MB | Apache-2.0 | v0.2 rules written from these (in-sample) |
| Splunk attack_data, `dev2` split | The 27 v1.0 holdout captures (23 single-technique, 4 malware family) | 716 MB | Apache-2.0 | v0.3 rules written from these (burned, in-sample) |
| Splunk attack_data, `sealed` split (`--split sealed`) | 160 further Linux captures, selected from the tree listing only | 1.8 MB | Apache-2.0 | Scored once with frozen v0.3 rules ([protocol](protocol.md)) |

## Citations

- A. Alsaheel, Y. Nan, S. Ma, L. Yu, G. Walkup, Z. B. Celik, X. Zhang, D. Xu.
  *ATLAS: A Sequence-based Learning Approach for Attack Investigation.*
  USENIX Security 2021.
- R. Rodriguez et al. *Open Threat Research Forge (OTRF) Security-Datasets.*
- Splunk Threat Research Team. *attack_data.*
- S. T. King, P. M. Chen. *Backtracking Intrusions.* SOSP 2003.
- Z. Xu et al. *High Fidelity Data Reduction for Big Data Security Dependency
  Analyses (CPR).* CCS 2016.

## ATLASv2 (not used yet)

ATLASv2 (bitbucket.org/sts-lab/atlasv2) re-runs the ATLAS attacks with Sysmon and
per-event ground truth, which would suit ROOTLINE's Sysmon loader. It is about 154 GB;
a usable subset would have to be selected and fetched inside a CI job, which is on the
roadmap.

## DARPA Transparent Computing (not used, and why)

E3/E5 CDM dumps are hundreds of GB per host, and the public ground truth is
narrative engagement reports rather than per-event labels. Different papers
derive different label sets. A CDM loader is on the roadmap. Numbers on hand-
labelled TC subsets are not reported, because they could not be compared with
anything.

## Committed fixtures

`tests/fixtures/` holds small, attributed excerpts (see `SOURCES.txt`), so CI
runs on real formats without the downloads.
