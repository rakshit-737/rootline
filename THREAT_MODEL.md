# ROOTLINE Threat Model

## Assets
- The monitored host (a lab VM).
- The **provenance record**: the event stream, the graph, and the hash-chain head.
- The derived artifacts (story JSON, STIX) that downstream tools such as REVENANT and CTI trust.

## Adversary (modeled)
A local intruder with user-level access who may escalate to root. Their goals are persistence, credential theft, lateral-movement prep, and **telemetry evasion**: deleting logs, editing records, and flooding the sensor.

## Trust boundaries
| Boundary | Trust | Notes |
| --- | --- | --- |
| Kernel (eBPF capture) to ingester | Semi-trusted | Capture happens in-kernel, which makes it harder to tamper with than userland logs. A root attacker can still unload probes. |
| Raw records to normalizer | **Untrusted** | Records may be attacker-influenced (argv, paths, comm). |
| Graph and hash chain to exporters | Trusted, after verification | |
| Exported story/STIX to consumers | Integrity-tagged | The chain head is embedded in the story. |

## Threats and mitigations (STRIDE-ish)

| Threat | Mitigation in MVP | Gap / TODO |
| --- | --- | --- |
| **Tampering:** edit or delete events after capture | SHA-256 hash chain over canonical events. `rootline verify --head` detects any change. Ingestion is append-only (out-of-order events are rejected). | The head must be shipped off-host (remote syslog or a WORM store) in near real time. A local root attacker can rewrite both the log and the head. |
| **Repudiation:** a log deletion hides activity | Unlink is itself a provenance event (RL-006). The deleted file stays a vertex. | |
| **Spoofing:** a fake `comm` (for example, renaming the implant to `sshd`) to hit allowlists | Rules also key on exe path and writable directories. Graph lineage is independent of the name. | Allowlists by comm are spoofable. Should bind them to exe path plus hash. |
| **DoS / evasion:** event floods that exhaust memory or hide activity in noise | Reduction merges repetition. Traversal caps at `max_nodes`. Strings are bounded (4 KiB) and argv is capped. | No backpressure or ring-buffer drop accounting yet. Lost events must be surfaced (TODO). |
| **Injection:** malicious paths or argv reaching exporters or UIs | NUL-stripping, path normalization, type checks, and JSON encoding. Mermaid labels are quote-escaped. | Any future UI must HTML-escape labels. |
| **Info disclosure:** stories contain paths, users, and IPs | Exports stay local by default. | Add redaction options before sharing. |
| **Sensor disablement:** root unloads the probes | Out of scope for the MVP. | Heartbeat or gap detection plus a remote collector. |

## Assumptions
- Clocks are monotonic per host. Multi-host merge needs clock-skew handling (TODO).
- Synthetic data is used for the tests. Real-world recall on DARPA TC / ATLAS has not been measured yet.

## Safety scope
Everything is observe-only. Any attack generation happens only as synthetic records, or inside an isolated VM the operator owns.
