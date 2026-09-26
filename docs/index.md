# ROOTLINE

**Provenance-graph attack reconstruction.** ROOTLINE turns host telemetry (Sysmon for Linux/Windows,
auditd, AUOMS, ATLAS audit logs, or a bpftrace probe) into an append-only, hash-chained provenance
graph, tags it with ATT&CK-mapped rules and an unsupervised anomaly ranker, and reconstructs the
attack story from one alert or IOC: **root cause, causal spine and blast radius**.

[Try the replay UI](demo/index.html){ .md-button .md-button--primary }
[Getting started](getting-started.md){ .md-button }
[Benchmarks](benchmarks.md){ .md-button }

![Attack-replay UI on the OTRF Log4Shell capture](img/replay-ui.png)

## Headline results (real public data)

- **ATLAS S1-S4:** at ~100 % recall, time-respecting traversal is 2.0-4.5x more precise than plain
  reachability from the same analyst IOC (F1 0.28-0.74 vs 0.15-0.39).
- **Graph reduction:** 3.8-4.4x fewer edges with 100 % of attack edges preserved.
- **Log4Shell (OTRF, Sysmon + AUOMS fused):** the reverse shell traces back through `java` to the
  attacker's LDAP `:1389` and HTTP `:8888` callbacks.
- **Tagger coverage (Splunk attack_data):** honest held-out numbers, and the rules overfit. See
  [Limitations](limitations.md).

## Outputs

`rootline.story/v1` JSON (with the hash-chain head, for REVENANT), a STIX 2.1 bundle, Mermaid and
Neo4j Cypher.

!!! warning "Lab use only"
    ROOTLINE analyses captured telemetry. It contains no exploit or malware code; the datasets are
    event logs downloaded outside the repository.
