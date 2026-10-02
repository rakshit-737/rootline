# CLI reference

Generated from the argparse parser at docs build time (`docs/hooks.py`), so it always matches `rootline --help`.

```text
usage: rootline [-h] [--version] {synth,analyze,verify,serve,demo} ...

Provenance-graph attack reconstruction

positional arguments:
  {synth,analyze,verify,serve,demo}
    synth               generate synthetic kernel events
    analyze             build graph, tag, reconstruct
    verify              print or check the provenance hash-chain head
    serve               FastAPI + attack-replay UI (needs rootline[api])
    demo                synthetic end-to-end demo

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

## rootline synth

```text
usage: rootline synth [-h] --out OUT [--truth TRUTH] [--benign BENIGN]
                      [--seed SEED] [--no-attack]

options:
  -h, --help       show this help message and exit
  --out OUT        output JSONL file
  --truth TRUTH    also write the ground-truth JSON here
  --benign BENIGN  number of benign sessions (default 300)
  --seed SEED      random seed (default 7)
  --no-attack      benign activity only
```

## rootline analyze

```text
usage: rootline analyze [-h] [--format {auto,jsonl,sysmon,auditd}] [--iforest]
                        [--cypher CYPHER] [--baseline BASELINE]
                        [--pivot PIVOT | --ioc IOC] [--story STORY]
                        [--stix STIX] [--mermaid MERMAID] [--no-reduce]
                        events [events ...]

positional arguments:
  events                one or more captures (several sensors are fused)

options:
  -h, --help            show this help message and exit
  --format {auto,jsonl,sysmon,auditd}
                        input format (default: sniffed)
  --iforest             also rank process vertices with IsolationForest
  --cypher CYPHER       write a Neo4j import script for the story
  --baseline BASELINE   benign JSONL capture used as the 'normal' baseline for
                        rarity rules
  --pivot PIVOT         vertex id to reconstruct from
  --ioc IOC             substring (path/ip) of a vertex to pivot on
  --story STORY         write the rootline.story/v1 JSON here
  --stix STIX           write a STIX 2.1 bundle here
  --mermaid MERMAID     write the story as a Mermaid flowchart here
  --no-reduce           skip the causality-preserving reduction
```

## rootline verify

```text
usage: rootline verify [-h] [--head HEAD]
                       [--format {auto,jsonl,sysmon,auditd}]
                       events

positional arguments:
  events                capture to hash (any supported format)

options:
  -h, --help            show this help message and exit
  --head HEAD           expected chain head; omit to print the head
  --format {auto,jsonl,sysmon,auditd}
                        input format (default: sniffed)
```

## rootline serve

```text
usage: rootline serve [-h] [--host HOST] [--port PORT] [--fuse] [captures ...]

positional arguments:
  captures     captures to analyse at start-up

options:
  -h, --help   show this help message and exit
  --host HOST  bind address (default 127.0.0.1; the API has no authentication)
  --port PORT  port (default 8000)
  --fuse       fuse all captures into one story (several sensors, one host)
```

## rootline demo

```text
usage: rootline demo [-h] [--outdir OUTDIR] [--benign BENIGN]

options:
  -h, --help       show this help message and exit
  --outdir OUTDIR  output directory (default out/)
  --benign BENIGN  number of benign sessions (default 400)
```
