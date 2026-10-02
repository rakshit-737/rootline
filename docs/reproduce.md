# Reproduce

Every published number comes from a script that writes a committed file under `results/`.
Runtimes are wall-clock on a Windows 11 laptop (16 GB RAM, Python 3.14) unless marked CI.
Set `ROOTLINE_DATA` to choose where datasets go (default `~/.cache/rootline`); nothing is
downloaded into the repository.

## Setup

```bash
git clone https://github.com/rakshit-737/rootline && cd rootline
pip install -e ".[dev,bench]"
export ROOTLINE_DATA=~/rootline-data
python scripts/download_data.py --list    # 78 files, 736.5 MB (the default set)
python scripts/download_data.py           # ATLAS S1 zip, OTRF, Splunk dev + dev2; SHA-256 and size checked
python scripts/download_data.py --source atlas --all   # + ATLAS M1 (62 MB, multi-host) and S2-S4 (repro)
```

## What regenerates what

| Result file | Command | Runtime | Where it ran |
|---|---|---|---|
| `results/atlas.json`, `RESULTS.md`, `figures/atlas_prf.png` | `python scripts/bench.py --only atlas` | ~25 min (16 logs, incl. IsolationForest x10 seeds) | laptop |
| `results/log4shell.json`, `log4shell_story.*` | `python scripts/bench.py --only log4shell` | < 1 s | laptop |
| `results/ablation.json`, `figures/ablation.png` | `python scripts/ablation.py` | 13 min (782 s) | laptop |
| `results/coverage.json`, `figures/tagger_coverage.png` | manual workflow **sealed-coverage** (runs `scripts/verify_freeze.py`, downloads the pinned captures, `scripts/bench.py --only coverage`) | ~6 min | CI run 36994398382 |
| `results/live_ebpf.json`, `live_ebpf_story.mmd` | `live-ebpf` job in `ci.yml` (`scripts/live/run_chain.sh` + `assert_chain.py`) | ~2 min per run | CI run 36996901332 |
| `results/atlas_repro.json` | manual workflow **atlas-repro** (`repro/atlas_repro.py`, 4 scenarios x 5 seeds, then `--merge`) | ~8 min (20 parallel jobs, 1-5 min each) | CI run 36997669262 |
| `results/TABLES.md` | `python scripts/render_tables.py` | < 1 s | anywhere |

The sealed coverage must not be re-scored with changed rules: `verify_freeze.py` fails if
the rules, loaders or normaliser differ from the pre-registered hashes (see
[the protocol](protocol.md)). Re-running the workflow at its default ref (the scored
commit) reproduces the published numbers exactly.

## Expected headline numbers

After the commands above, `results/TABLES.md` should show (see [Evaluation](evaluation.md)):

- Ablation, S1-S4: `full` precision 0.54, recall 0.98, F1 0.66; `naive` F1 0.25.
- Ablation, M hosts (held out): `full` precision 0.63, recall 0.72, F1 0.46; `naive` F1 0.33.
- Coverage, sealed: v0.3 detected 4/64 parsed captures.
- Live eBPF: 5/5 runs passed.

The traversals are deterministic. IsolationForest uses seeds 0-9 and the LSTM reproduction
seeds 0-4; their results vary within the reported intervals across hardware.

## Tests and docs

```bash
python -m pytest -q                 # unit + fixture tests; real-data tests skip without $ROOTLINE_DATA
python -m pytest -q -m realdata     # the tests that need the downloads
pip install -r requirements-docs.txt && mkdocs build --strict   # docs/hooks.py builds the demo and CLI page
```
