# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](https://semver.org/).

## [Unreleased]

### Added
- **Live eBPF in CI** (`live-ebpf` job, five runs per push): the bpftrace probe runs with
  sudo on the ubuntu-24.04 runner kernel while a benign chain runs entirely inside the
  runner (TEST-NET server on a dummy interface, throwaway `HOME`, dummy files); one
  query must recover the download socket as a root cause plus every chain step.
  Results in `results/live_ebpf.json`; ADR 0008 supersedes ADR 0007.
- **v0.3 rules** RL-019..024 (sudo/doas/setuid abuse, kernel modules, library
  hijacking and related techniques), written from the `dev` and `dev2` captures.
- **dev / dev2 / sealed rule protocol** (`docs/protocol.md`, ADR 0009): 160 sealed
  Splunk captures pinned at `attack_data@b4573ed3` by LFS SHA-256, a freeze check
  (`scripts/verify_freeze.py`) and the manual `sealed-coverage` workflow that scored
  them once (run 36994398382). Wilson 95 % intervals and an alert-precision proxy.
- **Ablation study** (`rootline.ablation`, `scripts/ablation.py`, ADR 0010):
  time-respecting traversal, session-root stops, causal spine and "accessed"
  expansion switched off one at a time, every ground-truth entity as a pivot,
  ATLAS S1-S4 (design data) vs the 12 M1-M6 host logs (held out), scenario-cluster
  bootstrap CIs and sign tests.
- **ATLAS reproduction** (`repro/atlas_repro.py`, manual `atlas-repro` workflow):
  PyTorch reimplementation of the ATLAS LSTM under the paper's setup, S1-S4 x 5 seeds,
  with ATLAS's shipped artefacts scored the same way (`results/atlas_repro.json`).
- IsolationForest baselines: a user-directory heuristic and a run without the
  `exec_user_dir` feature (`IForestTagger(drop=...)`, `userdir_ranking`).
- ATLAS M1 (multi-host) logs in the benchmarks; all ATLAS zips pinned to commit
  `e46096d` with SHA-256 and size.
- Docs: How it works, Evaluation, Reproduce and protocol pages; generated CLI
  reference; `docs/hooks.py` so a plain `mkdocs build --strict` works.
- Repo: issue/PR templates, CODEOWNERS, Dependabot, CITATION.cff; CI on Python
  3.10-3.14; private vulnerability reporting and secret scanning enabled.

### Changed
- **Probe v1.2**: self filtering by PID instead of process name; process creation
  from `wake_up_new_task` for new thread groups only (threads no longer appear as
  processes); `-f json` output with a fixed record layout; fd maps keyed by process
  start time; dup2/dup3 path tracking; `tsns=` timestamps.
- The default rule set is v0.3 (RL-001..024). The v1.0 `holdout` is renamed `dev2`
  and is in-sample for v0.3.
- IOCs: `ip` holds all external addresses, `ipv4`/`ipv6` split them by family;
  loopback, unspecified and link-local addresses and `/dev`, `/proc`, `/sys`, `/run`
  paths are never IOCs; IPv6 sockets are labelled `[addr]:port`.
- API: loopback-only Host allowlist, `X-Rootline: 1` required on POST, streamed
  upload cap, parsing in a worker thread, bounded story store, docs endpoints off
  by default; `serve` warns when bound off loopback.
- CLI: `verify` reads any format and fails on zero parsed events; one-line errors for
  missing files; `--iforest` checks for its extra first; help text on every option.
- Downloads: Splunk URLs pinned to a commit, size check, fail closed without a
  SHA-256; default data directory `~/.cache/rootline`.
- Packaging: SPDX licence string (setuptools >= 77), tests shipped in the sdist,
  `repro` extra, uvicorn in `dev`. Actions bumped to their Node-24 majors; release
  actions pinned by SHA.

### Fixed
- Cypher export: a root-cause path containing a newline could escape a `//` comment
  and inject a statement. Telemetry text is now only ever a quoted literal.
- Mermaid labels escape quotes and control characters.
- Sysmon `<Event>` extraction was quadratic on unterminated tags (ReDoS); it is now
  linear with a 1 MB line cap.
- Malformed numbers, deep JSON and non-finite timestamps no longer crash ingestion.
- The `/demo/` URL served a docs page instead of the replay UI (page renamed to
  `live-demo.md`, plus a CI guard).
- Release notes extraction from this file (awk escape bug); the v1.0.0 release body
  was corrected.
- `mean_ci` clips the 95 % t-interval to the metric's valid range (recall in
  [0, 1], hits in [0, min(k, malicious)], first-hit rank >= 1), so results no
  longer report impossible bounds such as recall@10 CI [0.837, 1.063].
  `scripts/bench.py --render-only` re-renders RESULTS.md from cached JSON.
- The live chain no longer writes into the real `~/.aws` and `~/.config` of whoever
  runs it; it refuses to run outside CI unless `ROOTLINE_LAB=1`.

### Results that got worse (published as is)
- Rule coverage on the sealed split: v0.3 detects 4 of 64 parsed captures (Wilson
  95 % [0.03, 0.15]); 96 of 160 sealed captures are not parsed by the frozen loaders.
- The ATLAS LSTM reproduction does not reach the paper's numbers (entity F1 0.24-0.75
  vs 0.89-1.00).
- On held-out ATLAS hosts the full reconstructor's F1 gain over naive reachability is
  not significant (recall 0.72), and from the analyst IOC the story collapses on 5 of 6
  second-hop hosts.
- IsolationForest process ranking is beaten by a one-line user-directory heuristic
  (new baseline), and falls to recall@10 0.49 without its `exec_user_dir` feature.

## [1.0.0] - 2026-09-26

Docs site, static demo, release pipeline, and statistically honest anomaly numbers.

### Added
- MkDocs Material documentation site on GitHub Pages
  (https://rakshit-737.github.io/rootline/), with architecture, datasets,
  benchmarks, CLI, Python API (mkdocstrings) and HTTP API reference, the threat
  model, ADRs and limitations. It is built with `mkdocs build --strict`.
- A static build of the attack-replay UI under `/demo/`
  (`scripts/build_demo.py`). It is rendered from the committed Log4Shell excerpt
  and one synthetic intrusion.
- Release workflow: on a `v*` tag it pushes the image to
  `ghcr.io/rakshit-737/rootline` and creates a GitHub Release with the wheel and
  sdist.
- CI: a Docker image job that checks the preloaded story is served, and a
  docker-compose job that imports the Cypher export into Neo4j.
- Committed benchmark results (`results/`): ATLAS S1-S4, Splunk dev/holdout
  coverage, OTRF Log4Shell fusion, plus figures.
- `rootline serve --fuse` loads several sensor captures as one story.
- `Dockerfile` and `docker-compose.yml`, with a Neo4j service for Cypher
  imports.

### Changed
- The IsolationForest benchmark now runs 10 seeds and reports the mean with a
  95 % t-interval, instead of a single seed.

### Fixed
- `reduction_stats` rebuilt the attack-sequence set for every edge (O(E*N)).
  ATLAS S3 took about 10 minutes and now takes under a second. Each ATLAS graph
  is also built once and shared across benchmarks.

## [0.2.0] - 2026-09-26

Real public data, real benchmarks, and the spec features the MVP left as TODO.

### Added
- **Real-data loaders** (`rootline.loaders`):
  - Sysmon for Linux and Windows XML, including Syslog-JSON and syslog-prefixed
    lines. DTDs are rejected.
  - Raw auditd, with multi-line records grouped by serial.
  - Microsoft AUOMS.
  - ATLAS pre-processed, line-labelled audit logs.
  - Format sniffing, plus `merge_sources()` to fuse several sensors on one host
    (exec dedup).
- `dns` event kind. Socket vertices carry their resolved domains.
- **Command-line ATT&CK rules RL-008..RL-018** (`rules_linux.py`): GTFOBins sudo
  shell escapes, decode/obfuscation, ingress transfer, destruction, impaired
  defenses, tunnelling, scripted ssh, clipboard reads, PwnKit / `login -f` /
  user-dir execution, system-lib implants, discovery bursts. The v0.1 rules stay
  available as `RULES_V01`.
- **IsolationForest process-vertex tagger** (`anomaly.py`, `[ml]` extra) and a
  degree-ranking baseline.
- **Multi-seed IOC reconstruction.** An attacker IP that maps to several sockets
  is traced from first contact.
- **Benchmarks** (`rootline.bench`, `scripts/bench.py`):
  - ATLAS S1-S4 reconstruction against IOC-grep and naive-reachability baselines.
  - Reduction and attack-edge preservation.
  - Anomaly ranking.
  - Tagger coverage on Splunk attack_data with a never-inspected held-out split.
  - OTRF Log4Shell single-sensor vs fused.
  - Results go to `results/`.
- `scripts/download_data.py` with a checksummed manifest (ATLAS, OTRF, Splunk).
  Idempotent zip extraction with path-traversal checks.
- **FastAPI service and attack-replay UI** (`rootline serve`, `[api]` extra).
- **Neo4j Cypher export** (`--cypher`, `to_cypher`). The STIX bundle is validated
  with `stix2` in tests.
- CLI: several captures per `analyze`, plus `--format`, `--iforest`, `--cypher`
  and `serve`.
- Docs: `docs/adr/0001-0007`, `docs/datasets.md`, `CONTRIBUTING.md`,
  `CHANGELOG.md`, `LICENSE` (MIT).
- CI: ruff lint job, standard-library-only job, real-capture smoke test.

### Changed
- Forward traversal now crosses a socket root's `RECEIVED` edge. Before this, the
  causal spine from a network entry point collapsed to the socket itself.
- A root-cause candidate must feed the slice strictly before the pivot. The C2
  socket the pivot opened is no longer reported as its own cause.
- Forward traversal no longer expands through session and service roots. The
  "accessed" set is limited to processes the intrusion created. Entry scoring
  understands Windows paths and penalises app-state churn.
- Kill-chain stages add privilege-escalation, discovery, lateral-movement and
  collection.

### Fixed
- The AUOMS header (`audit(...)` without `msg=`) was not parsed, so the loader
  returned 0 records.

## [0.1.0] - 2026-09

- MVP:
  - Normalizer, append-only hash-chained provenance graph and CPR-style
    reduction.
  - Seven ATT&CK-mapped rules and a rare-transition model.
  - Time-respecting backward/forward reconstruction.
  - Story JSON, STIX 2.1 and Mermaid exports.
  - Synthetic generator, CLI and bpftrace reference probe.
