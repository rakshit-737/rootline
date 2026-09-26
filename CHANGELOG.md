# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[SemVer](https://semver.org/).

## [Unreleased]

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
