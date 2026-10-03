# Limitations and roadmap

## Limitations

- **The reconstructor was designed on ATLAS S1-S4.** On held-out M1-M6 hosts its precision gain
  holds but recall drops to 0.72 and the F1 gain over naive reachability is not significant
  (higher on 9 of 12 logs, sign-flip p = 0.28; [Evaluation](evaluation.md)). Only the
  session-root stops transfer cleanly.
- **"Held out" means unseen host logs from the same testbed.** 8 of the 12 held-out logs replay
  an exploit (and, per the ATLAS paper's Table 2, an APT report) that S1-S4 also use. Only the
  four M2 and M4 logs carry a new exploit; the stops effect holds there too (+0.12 precision,
  higher on 4 of 4), but four logs are descriptive evidence only.
- **Precision on ATLAS stays modest (0.54-0.62 for the full method).** ATLAS labels every line
  that involves a malicious entity, including benign services that merely read `payload.exe`,
  and traversal pulls in benign activity inside the attacker's process tree. None of the
  high-recall variants exceeds 0.62 precision; seed-plus-one-hop IOC grep reaches about 1.0
  precision at about 4 % recall.
- **Entry-point ranking is weak.** Root-cause hit@3 ranges from 0.40 to 0.50 across variants.
- **Small samples.** The design data is four logs: no distribution-free test on them can reach
  p < 0.125, so S1-S4 results are reported as per-log ranges and a t(3) interval.
- **Event universe.** ROOTLINE can represent 63-73 % of the lines ATLAS labels as attack (no
  browser rows, no pid-less rows, no audit lines without a file or network operation).
- **The rules do not generalise.** v0.3 detects 4 of 64 parsed sealed captures, and 96 of
  160 sealed captures are not parsed by the loaders at all (mostly auditd variants).
- **The sealed numbers belong to commit 60e3561.** After the scoring run the normaliser,
  graph and Sysmon/auditd loaders were hardened (logic changes) and docstrings were edited in
  the frozen rule files (no logic change). Every release since v1.1.0 therefore ships a
  post-freeze loader version, and any sealed re-score at a later commit is in-sample. Re-scoring
  the in-sample dev/dev2 splits with the current code reproduces all 73 rows. See the
  [protocol](protocol.md#state-after-scoring).
- **The ATLAS LSTM reproduction does not reach the paper's numbers**, nor ATLAS's own cleaned
  entity list scored the same way; ATLAS's shipped raw model output does not either.
- **Live probe scope.** The probe runs live in CI (bpftrace on a GitHub-hosted kernel, not a
  libbpf CO-RE probe) on a scripted, benign chain. Relative paths are not resolved against
  the cwd, `dup()`/`fcntl` and fork-inherited fds are not mapped, argv is not captured and
  paths are cut at 64 bytes. Over 15 pushes (72 completed jobs) the live check passed 71
  times; the failure was a too-strict fork-parent check (since corrected), and the chain was
  recovered in all 72 (one row per job in `results/live_ebpf.json`).
- **Reduction is lossless and does not change accuracy.** Vertex counts do not change on
  ATLAS; lossy reduction is future work.
- The ATLAS scenarios are Windows. The Linux evidence comes from OTRF, Splunk and the live CI
  chain.
- **Input encoding.** A JSONL capture that is not UTF-8 text is refused as a whole (one-line CLI
  error, HTTP 422) rather than decoded line by line, because the JSONL reader is one of the
  frozen v0.3 sources.
- **Docstrings in the frozen sources.** 28 public functions in `detect.py`, `normalize.py`,
  `rules_linux.py` and the Sysmon/auditd loaders have no docstring. Every other public class,
  method and function has one (ruff D101-D103 in CI), and the frozen files are left untouched.
- **Supply chain.** First-party and third-party actions, the base image and the Neo4j image are
  pinned by SHA or digest, and the image installs its dependencies from a hash-locked file.
  Two parts are not pinned: the build backend that `pip install .` fetches for the package
  itself, and the actions in `sealed.yml`, which is part of the sealed-protocol record and is
  not edited.
- The SentinelCore field map is an assumption until it is aligned with the real schema.
- Neo4j support is an export (Cypher), imported in CI; ROOTLINE does not query Neo4j.

## Roadmap

- [x] Real-data loaders (Sysmon, auditd, AUOMS, ATLAS) and multi-sensor fusion
- [x] ATLAS / Splunk / OTRF benchmarks against baselines
- [x] IsolationForest tagger, FastAPI + replay UI, STIX validation, Neo4j Cypher export
- [x] Live bpftrace probe in a privileged CI job (v1.2: PID self-filter, JSON records)
- [x] ATLAS M1-M6 host logs as held-out data; component ablation with log-level tests
- [x] Sealed rule evaluation; ATLAS LSTM reproduction attempt
- [x] Result files regenerated in CI with a provenance block (commit, run id)
- [ ] Loaders for the auditd variants that the sealed split exposed, and per-line handling of
      non-UTF-8 input (as a new loader version, scored in-sample)
- [ ] Probe: absolute paths via `security_file_open`/`path()`, dup/fcntl/fork fd tracking, lost-event accounting in long runs
- [ ] Better entry-point ranking (root-cause hit@3 is 0.40-0.50)
- [ ] Live multi-sensor ablation: auditd and Sysmon for Linux next to bpftrace in the CI chain
      (deferred: each extra sensor adds install and run time to every push's five live jobs)
- [ ] Leave-one-scenario-out redesign of the traversal heuristics, and LSTM retraining on M2-M6
      (deferred: needs the 224 MB M2-M6 experiment data and several hours of CPU training in CI)
- [ ] A 1M-event capture reduced to a 40-node story as a demo scenario (deferred: new feature
      scope, depends on lossy reduction below)
- [ ] DARPA TC CDM loader (streaming, one host subset); ATLASv2 (154 GB, needs a CI-side subset)
- [ ] Lossy template reduction, streaming `analyze --follow`, a GNN node-anomaly stretch goal
- [ ] Align the SentinelCore field map with SentinelCore's real event schema
