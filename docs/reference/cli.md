# CLI reference

```text
rootline {synth,analyze,verify,serve,demo}
```

| Command | Purpose |
|---|---|
| `rootline analyze EVENTS... [--format auto|jsonl|sysmon|auditd] [--pivot ID | --ioc STR] [--iforest] [--no-reduce] [--story F] [--stix F] [--mermaid F] [--cypher F] [--baseline F]` | Build the graph from one or more captures (several are fused), tag, reconstruct and export |
| `rootline verify EVENTS [--head HASH]` | Print the hash-chain head, or check it; exit code 2 on mismatch |
| `rootline serve [CAPTURES...] [--fuse] [--host H] [--port P]` | FastAPI + replay UI (`[api]` extra) |
| `rootline demo [--outdir D] [--benign N]` | Synthetic end-to-end intrusion |
| `rootline synth` | Generate synthetic kernel events (JSONL) |

Exit codes: `0` success, `2` integrity check failed.
