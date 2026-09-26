# ADR 0006: Loaders map to one raw-record contract; sensors are fused per host

- Status: accepted (v0.2)

## Context

Each real telemetry source sees part of the picture. In OTRF's Log4Shell capture,
Sysmon for Linux records java's LDAP and HTTP callbacks to the attacker but
**not** the `execve` whose parent is java. Microsoft AUOMS (auditd) records that
`execve` (`pid=17790 ppid=1340`) but has no network events. With either one
alone, the reverse shell's lineage stops before the exploited JVM.

## Decision

- Every loader (Sysmon XML/Syslog-JSON, raw auditd, AUOMS, ATLAS CSV, ROOTLINE
  JSONL, bpftrace `k=v`) yields the **same raw-record dicts** the normalizer
  already validates. Graph, rules and reconstruction never see a format.
- `merge_sources()` merges streams in time order. Host names are compared
  case-insensitively. An `exec` of the same image by the same PID within 1 s is
  kept once, and the first source wins. The CLI and API fuse automatically when
  given several captures.
- `dns` is a first-class event (domain to IP). It annotates socket vertices
  instead of creating process edges.
- Parsers treat input as hostile. Any Sysmon document with a `<!` (DTD or ENTITY)
  is rejected before `ElementTree` sees it, so XXE and billion-laughs attacks
  cannot happen. Malformed lines are counted and skipped, and zip extraction in
  the download script refuses path traversal.

## Consequences

- On Log4Shell, fusion extends the story from `bash -> reverse shell` to
  `java <- LDAP:1389 / HTTP:8888 -> bash -> 443 -> whoami` (`results/log4shell.json`).
- Clock skew between sensors beyond the 1 s window would duplicate exec vertices.
  Real deployments need a sensor-side clock sync, which is documented as a
  limitation.
