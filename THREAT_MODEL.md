# ROOTLINE Threat Model

## Assets
- The monitored host (a lab VM or a CI runner).
- The **provenance record**: the event stream, the graph, and the hash-chain head.
- The derived artefacts (story JSON, STIX, Cypher) that downstream tools such as REVENANT, CTI platforms and Neo4j trust.

## Adversary (modelled)
A local intruder with user-level access who may escalate to root. Their goals are persistence, credential theft, lateral-movement preparation, and **telemetry evasion**: deleting logs, editing records, flooding the sensor, or making their own activity invisible to it.

## Trust boundaries
| Boundary | Trust | Notes |
| --- | --- | --- |
| Kernel (eBPF capture) to ingester | Semi-trusted | Capture happens in-kernel, which makes it harder to tamper with than userland logs. A root attacker can still unload probes. |
| Raw records to normaliser | **Untrusted** | Paths and process names are attacker-chosen. |
| Graph and hash chain to exporters | Trusted, after verification | |
| Exported story/STIX/Cypher to consumers | Integrity-tagged | The chain head is embedded in the story; all strings are escaped for the target language. |
| Browser to local API | **Untrusted** | No authentication; loopback Host allowlist and a custom POST header. |

## Threats and mitigations

| Threat | Mitigation | Gap |
| --- | --- | --- |
| **Tampering:** edit or delete events after capture | SHA-256 hash chain over canonical events; `rootline verify --head` detects any change and refuses to "verify" an input with zero parsed events. | The head must be shipped off-host in near real time. A local root attacker can rewrite both the log and the head. |
| **Repudiation:** a log deletion hides activity | Unlink is itself a provenance event (RL-006; exercised live in CI). The deleted file stays a vertex. | |
| **Sensor evasion by name:** a process renames itself to look like the tracer | The probe filters on its own **PID**, not its name; CI runs a decoy named `bpftrace` and asserts it is still captured. | |
| **Record forgery:** a file or process name containing newlines or `key=value` text | Probe output is JSON (`bpftrace -f json`); records are parsed with an anchored pattern (numeric fields fixed, free text last); control characters are made visible. Legacy plain-text captures are still readable but documented as forgeable. | |
| **Spoofing:** a fake `comm` (for example, renaming the implant to `sshd`) to hit allowlists | Rules also key on exe path and writable directories. Graph lineage is independent of the name. | Session-root stops are keyed on the process name and can be abused to cut a backward trace; binding them to exe path plus hash is future work. |
| **DoS / evasion:** event floods or oversized input | Reduction merges repetition. Traversal caps at `max_nodes`. Strings are bounded (4 KiB), argv capped, Sysmon event extraction is linear-time with a 1 MB line cap, uploads are size-capped and parsed off the event loop, the story store is bounded. | The probe has no ring-buffer backpressure; CI asserts zero lost events but production use would need drop accounting. |
| **Injection into exporters / UI** | Cypher literals escape quotes, backslashes and control characters, and no telemetry goes into comments; Mermaid labels use entity codes; the UI HTML-escapes labels. Regression tests cover a newline-plus-Cypher payload in a root-cause path. | |
| **Cross-site / DNS rebinding against the local API** | TrustedHost allowlist (loopback names), `X-Rootline: 1` required on POST, docs endpoints off by default. | No authentication; do not expose it. |
| **Info disclosure:** stories contain paths, users and IPs | Exports stay local by default. | Add redaction options before sharing. |
| **Sensor disablement:** root unloads the probes | Out of scope. | Heartbeat or gap detection plus a remote collector. |

## Assumptions
- Clocks are monotonic per host. Multi-host merge needs clock-skew handling.
- ATLAS recall and precision are measured on public labelled data (see the Evaluation page); the live probe is exercised only on a scripted, benign chain in CI.

## Safety scope
Everything is observe-only. Attack-shaped activity happens only as synthetic records, or as benign scripted commands with dummy files inside a throwaway CI runner.
