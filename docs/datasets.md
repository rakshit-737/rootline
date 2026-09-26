# Datasets

Everything is fetched by `python scripts/download_data.py` into
`../../datasets/rootline` (or `$ROOTLINE_DATA`), **outside the repository**,
with SHA-256 checks. `scripts/data_manifest.json` is the single source of truth.
No dataset contains executable content: they are event logs and pre-processed
audit CSVs. ATLAS model weights (`*.h5`) are skipped on extraction.

| Source | What | Size | Licence | Used for |
| --- | --- | --- | --- | --- |
| [ATLAS artefact](https://github.com/purseclab/ATLAS) `paper_experiments/S1.zip` | 4 single-host Windows attack scenarios (CVE-2015-5122, CVE-2015-3105, CVE-2017-11882, CVE-2017-0199). Line-labelled audit + DNS + Firefox logs | 13.7 MB zip, ~105 MB extracted | Apache-2.0 | Reconstruction, reduction and anomaly benchmarks |
| ATLAS `M1.zip` (optional, `--all`) | Multi-host scenarios M1-M6 | 62 MB | Apache-2.0 | Not in the headline results (download unreliable) |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) Log4Shell compound | Sysmon for Linux + AUOMS from one CVE-2021-44228 exploitation | < 1 MB | MIT | Real Linux case study, sensor fusion |
| OTRF atomic Linux | `sh_arp_cache`, `sh_binary_padding_dd` (raw auditd) | < 5 KB | MIT | Loader tests |
| [Splunk attack_data](https://github.com/splunk/attack_data), `dev` split | 46 Sysmon-for-Linux captures, one ATT&CK technique each | ~6 MB | Apache-2.0 | Tagger coverage (in-sample) |
| Splunk attack_data, `holdout` split | 27 further captures, never inspected while writing rules | ~0.3 GB | Apache-2.0 | Tagger coverage (out-of-sample) |

## Citations

- A. Alsaheel, Y. Nan, S. Ma, L. Yu, G. Walkup, Z. B. Celik, X. Zhang, D. Xu.
  *ATLAS: A Sequence-based Learning Approach for Attack Investigation.*
  USENIX Security 2021.
- R. Rodriguez et al. *Open Threat Research Forge (OTRF) Security-Datasets.*
- Splunk Threat Research Team. *attack_data.*
- S. T. King, P. M. Chen. *Backtracking Intrusions.* SOSP 2003.
- Z. Xu et al. *High Fidelity Data Reduction for Big Data Security Dependency
  Analyses (CPR).* CCS 2016.

## DARPA Transparent Computing (not used, and why)

E3/E5 CDM dumps are hundreds of GB per host, and the public ground truth is
narrative engagement reports rather than per-event labels. Different papers
derive different label sets. A CDM loader is on the roadmap. Numbers on hand-
labelled TC subsets are not reported, because they could not be compared with
anything.

## Committed fixtures

`tests/fixtures/` holds small, attributed excerpts (see `SOURCES.txt`), so CI
runs on real formats without the downloads.
