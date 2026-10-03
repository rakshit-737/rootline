# Reproduce

Every published number comes from a script that writes a committed file under `results/`, and
every such file records where it was made: a `provenance` block (script, rootline version,
commit, GitHub workflow and run id, Python, platform) or, for the older CI files, `run_id` and
`commit` fields. Set `ROOTLINE_DATA` to choose where datasets go (default `~/.cache/rootline`);
nothing is downloaded into the repository.

## Setup

```bash
git clone https://github.com/rakshit-737/rootline && cd rootline
pip install -e ".[dev,bench]"
export ROOTLINE_DATA=~/rootline-data
python scripts/download_data.py --list    # 78 files, 736.5 MB (the default set)
python scripts/download_data.py           # ATLAS S1 zip, OTRF, Splunk dev + dev2; SHA-256 and size checked
python scripts/download_data.py --only atlas/S1.zip atlas/M1.zip   # what the ATLAS benchmarks need (76 MB)
```

## What regenerates what

| Result file | Command | Runtime | Where the committed file was made |
|---|---|---|---|
| `results/atlas.json`, `figures/atlas_prf.png` | `python scripts/bench.py --only atlas` | 85 s in CI (16 logs, IsolationForest x10 seeds x2 variants) | manual workflow **bench**, run 37092501921 at cde2a39 |
| `results/log4shell.json`, `log4shell_story.*` | `python scripts/bench.py --only log4shell` | < 1 s | bench run 37092501921 |
| `results/ablation.json`, `figures/ablation*.png` | `python scripts/ablation.py` | 100 s in CI | bench run 37092501921 |
| `results/coverage_head.json` (dev/dev2 at HEAD, in-sample) | `python scripts/bench.py --only coverage --allow-unfrozen` | about 2 min in CI, including the 0.72 GB download | bench run 37092501921 |
| `results/coverage.json`, `figures/tagger_coverage.png` | manual workflow **sealed-coverage** (runs `scripts/verify_freeze.py`, downloads the pinned captures, `scripts/bench.py --only coverage`) | about 3 min (2 min 34 s) | CI run 36994398382 at 60e3561 (scored once) |
| `results/live_ebpf.json` (`run1_detail`), `live_ebpf_story.mmd` | `live-ebpf` job in `ci.yml` (`scripts/live/run_chain.sh` + `assert_chain.py`) | about 2 min per job | CI run 36996901332 |
| `results/live_ebpf.json` (`repeatability`) | `python scripts/live/collect_repeatability.py --first 36996901332 --last 37003827535 --dependabot-window 2026-10-01 2026-10-02` (downloads the live-ebpf artefacts with `gh`) | about 2 min | collected 2026-10-03 from 15 ci runs |
| `results/atlas_repro.json` | manual workflow **atlas-repro** (`repro/atlas_repro.py`, 4 scenarios x 5 seeds, then `--merge`) | about 8 min (20 parallel jobs, 1-5 min each) | CI run 36997669262 |
| `results/RESULTS.md` | `python scripts/bench.py --render-only` | < 1 s | anywhere |
| `results/TABLES.md` | `python scripts/render_tables.py` (`--check` verifies it is current) | < 1 s | anywhere |

`python scripts/bench.py` with no arguments runs atlas and log4shell and reuses the other
results, printing `reused results/X.json (not re-run)` for them. It exits with an error,
without writing anything, when a dataset it needs is missing.

The sealed coverage must not be re-scored with changed sources. `scripts/bench.py --only
coverage` runs `scripts/verify_freeze.py` first and refuses to write `results/coverage.json`
unless it passes, which at HEAD it does not: the loaders and normaliser were hardened after
scoring ([state after scoring](protocol.md#state-after-scoring)). Re-running the
`sealed-coverage` workflow at its default ref (the scored commit 60e3561) reproduces the
published numbers exactly. To confirm the freeze yourself:

```bash
python scripts/verify_freeze.py --ref 153eade    # freeze commit: "freeze intact at 153eade"
python scripts/verify_freeze.py --ref 60e3561    # scored commit: "freeze intact at 60e3561"
python scripts/verify_freeze.py --ast 153eade --files src/rootline/rules_v03.py src/rootline/rules_linux.py src/rootline/detect.py
```

## Expected headline numbers

After the commands above, `results/TABLES.md` should show (see [Evaluation](evaluation.md)):

- Ablation, S1-S4: `full` precision 0.54, recall 0.98, F1 0.66; `naive` F1 0.25.
- Ablation, M hosts (held out): `full` precision 0.62, recall 0.72, F1 0.46; `naive` F1 0.33;
  session-root stops +0.10 precision, higher on 12 of 12 logs.
- Coverage, sealed: v0.3 detected 4/64 parsed captures.
- Live eBPF: each push's five live-ebpf jobs normally all pass; over the window above, 71 of
  72 completed jobs passed and the chain was recovered in all 72.

The traversals are deterministic, and the CI runs set `PYTHONHASHSEED=0`. Regenerating the
ATLAS, ablation and Log4Shell files in CI reproduced every row of the earlier laptop files
exactly. IsolationForest uses seeds 0-9 and the LSTM reproduction seeds 0-4; their results can
vary within the reported spread across hardware and library versions.

## Tests and docs

```bash
python -m pytest -q                 # unit + fixture tests; real-data tests skip without $ROOTLINE_DATA
python -m pytest -q -m realdata     # the tests that need the downloads
pip install -r requirements-docs.txt && mkdocs build --strict   # docs/hooks.py builds the demo and CLI page
```
