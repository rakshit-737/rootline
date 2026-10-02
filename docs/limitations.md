# Limitations and roadmap

## Limitations

- **The reconstructor was designed on ATLAS S1-S4.** On held-out M1-M6 hosts its precision gain
  holds but recall drops to 0.72 and the F1 gain over naive reachability is not significant
  ([Evaluation](evaluation.md)). Only the session-root stops transfer cleanly.
- **Precision on ATLAS stays modest (0.54-0.63 for the full method).** ATLAS labels every line
  that involves a malicious entity, including benign services that merely read `payload.exe`,
  and traversal pulls in benign activity inside the attacker's process tree. None of the
  high-recall variants exceeds 0.63 precision; seed-plus-one-hop IOC grep reaches about 1.0
  precision at about 4 % recall.
- **Entry-point ranking is weak.** Root-cause hit@3 is about 0.45-0.48 in every variant.
- **Event universe.** ROOTLINE can represent 63-73 % of the lines ATLAS labels as attack (no
  browser rows, no pid-less rows, no audit lines without a file or network operation).
- **The rules do not generalise.** v0.3 detects 4 of 64 parsed sealed captures, and 96 of
  160 sealed captures are not parsed by the loaders at all (mostly auditd variants).
- **The ATLAS LSTM reproduction does not reach the paper's numbers**, and neither does
  ATLAS's own shipped raw model output.
- **Live probe scope.** The probe runs live in CI (bpftrace on a GitHub-hosted kernel, not a
  libbpf CO-RE probe) on a scripted, benign chain. Relative paths are not resolved against
  the cwd, `dup()`/`fcntl` and fork-inherited fds are not mapped, argv is not captured and
  paths are cut at 64 bytes. Over 9 pushes (42 completed jobs) the live check passed 41
  times; the failure was a too-strict fork-parent check (since corrected), and the chain
  itself was recovered every time.
- **Reduction is lossless and does not change accuracy.** Vertex counts do not change on
  ATLAS; lossy reduction is future work.
- The ATLAS scenarios are Windows. The Linux evidence comes from OTRF, Splunk and the live CI
  chain.
- The SentinelCore field map is an assumption until it is aligned with the real schema.
- Neo4j support is an export (Cypher), imported in CI; ROOTLINE does not query Neo4j.

## Roadmap

- [x] Real-data loaders (Sysmon, auditd, AUOMS, ATLAS) and multi-sensor fusion
- [x] ATLAS / Splunk / OTRF benchmarks against baselines
- [x] IsolationForest tagger, FastAPI + replay UI, STIX validation, Neo4j Cypher export
- [x] Live bpftrace probe in a privileged CI job (v1.2: PID self-filter, JSON records)
- [x] ATLAS M1-M6 host logs as held-out data; component ablation with CIs
- [x] Sealed rule evaluation; ATLAS LSTM reproduction attempt
- [ ] Loaders for the auditd variants that the sealed split exposed (as a new version, scored in-sample)
- [ ] Probe: absolute paths via `security_file_open`/`path()`, dup/fcntl/fork fd tracking, lost-event accounting in long runs
- [ ] Better entry-point ranking (root-cause hit@3 is ~0.45)
- [ ] DARPA TC CDM loader (streaming, one host subset); ATLASv2 (154 GB, needs a CI-side subset)
- [ ] Lossy template reduction, streaming `analyze --follow`, a GNN node-anomaly stretch goal
