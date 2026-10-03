# Getting started

## Try it in 60 seconds

```bash
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/rootline:latest
# open http://127.0.0.1:8000 - the replay UI, preloaded with the OTRF Log4Shell capture
```

or, without Docker (Python 3.10+, the core needs no third-party packages):

```bash
git clone https://github.com/rakshit-737/rootline && cd rootline
pip install -e .
rootline analyze tests/fixtures/log4shell_sysmon.json tests/fixtures/log4shell_auoms.json
```

The complete output (deterministic, about 0.4 s):

```text
[+] graph: {'events': 108, 'nodes': 105, 'edges': 111, 'process': 83, 'socket': 5, 'file': 17}  (rejected records: 0)
[+] reduction: {'edges_before': 111, 'edges_after': 108, 'nodes_before': 105, 'nodes_after': 96, 'edge_ratio': 1.03}
[+] alerts: 2
    RL-009  medium   T1140      base64 decoding: base64 -d
    RL-003  critical T1071      bash opened outbound connection to 192.168.2.6:443 (reverse shell / C2)

[*] pivot: RL-003 on bash[17806]
[*] root cause(s): ['192.168.2.6:8888', '192.168.2.6:1389']
[*] story: 13 nodes / 18 edges (backward 9, forward 4, accessed 2)
[*] kill chain:
    initial-access: 192.168.2.6:8888  (+1 more)
    command-and-control: bash[17806] connected to 192.168.2.6:443  (+1 more)
[*] IOCs: {"ip": ["192.168.2.6"], "ipv4": ["192.168.2.6"], "ipv6": [], "files": [], "sha256": []}
[*] integrity head: d1b6e3cde1f07bcf93a670231d4002586cfbab5a7aa3b935a75b910176898656
```

The reverse shell traces back through `java[1340]` to the attacker's LDAP (`:1389`) and HTTP
(`:8888`) callbacks: the JNDI exploitation chain. The two files are the full OTRF capture,
recorded by two sensors on one host (Sysmon for Linux and AUOMS), which ROOTLINE fuses. The
integrity head is the SHA-256 hash-chain head of the provenance record; `rootline verify` checks it.

## More commands

```bash
rootline demo --outdir out                                   # synthetic intrusion -> out/events.jsonl, story.json, stix.json, story.mmd
rootline analyze out/events.jsonl --ioc 203.0.113.66         # pivot on an IOC instead of the top alert
rootline verify out/events.jsonl                             # print the hash-chain head
rootline verify out/events.jsonl --head "$(rootline verify out/events.jsonl)"   # exit 0; exit 2 if the record was altered
rootline analyze tests/fixtures/log4shell_sysmon.json tests/fixtures/log4shell_auoms.json \
        --story story.json --stix stix.json --mermaid story.mmd --cypher story.cypher
```

Optional extras:

```bash
pip install -e ".[ml]"     # rootline analyze ... --iforest   (IsolationForest process ranking)
pip install -e ".[api]"    # rootline serve --fuse tests/fixtures/log4shell_sysmon.json tests/fixtures/log4shell_auoms.json
pip install -e ".[dev]"    # tests and lint: python -m pytest -q
docker compose up          # UI plus a Neo4j browser on 127.0.0.1:7474 (set NEO4J_PASSWORD)
```

`rootline serve` binds to 127.0.0.1 and has no authentication; see [Security](security.md).

## Next

- [How it works](how-it-works.md) follows one live capture through the pipeline.
- [Evaluation](evaluation.md) has every result with its methodology and confidence intervals.
- [Reproduce](reproduce.md) lists the exact commands that regenerate them.
