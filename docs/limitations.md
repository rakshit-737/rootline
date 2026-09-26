# Limitations and roadmap

## Limitations

- **Precision on ATLAS is modest (0.16–0.59).** ATLAS labels every line that involves a malicious entity, including benign services that merely read `payload.exe`. Traversal also pulls in benign activity inside the attacker's process tree. No causality-only method can reach perfect precision on these labels.
- **Reduction does not change accuracy.** It is designed to be lossless. More aggressive, lossy reduction (NodeMerge/templates) is future work.
- **The rules overfit.** Holdout coverage is 44 % with any alert and 19 % with the correct technique.
- **The eBPF probe is a documented reference.** It is not run in CI or on a live host from this Windows development machine ([ADR 0007](adr/0007-ebpf-probe-as-reference.md)). Tamper resistance is shown with the hash chain, not measured in-kernel.
- The ATLAS scenarios are Windows. The Linux evidence comes from OTRF and Splunk, which are real but small single-technique captures.
- The SentinelCore field map is still an assumption until it is aligned with the real schema.
- Neo4j support is an export (Cypher script), not a live store. CI brings up the docker-compose stack and imports the Log4Shell story into Neo4j, but ROOTLINE does not query Neo4j itself.

## Roadmap

- [x] Real-data loaders (Sysmon, auditd, AUOMS, ATLAS) and multi-sensor fusion
- [x] ATLAS / Splunk / OTRF benchmarks against baselines, with a held-out split
- [x] IsolationForest tagger, FastAPI + replay UI, STIX validation, Neo4j Cypher export
- [ ] DARPA TC CDM loader (streaming, one host subset) with community label sets
- [ ] ATLAS multi-host M1–M6 (the download is in the manifest as `--all`)
- [ ] libbpf CO-RE ring-buffer probe with fd→path for `write()`, run in a privileged Linux CI job
- [ ] Lossy template reduction, and a GNN node-anomaly stretch goal

