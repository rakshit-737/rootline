# Getting started

Requires Python 3.10 or newer. The core engine uses only the standard library.

```bash
git clone https://github.com/rakshit-737/rootline && cd rootline
pip install -e ".[dev]"            # core + test deps
python -m pytest -q                # real-data tests skip when the data is absent
rootline demo --outdir out         # synthetic intrusion -> story.json, stix.json, story.mmd
```

## Analyse a real capture

The repository ships a small excerpt of the OTRF Log4Shell capture (CVE-2021-44228), recorded by
two sensors on one host. ROOTLINE fuses them:

```bash
rootline analyze tests/fixtures/log4shell_sysmon.json tests/fixtures/log4shell_auoms.json \
        --story story.json --stix stix.json --mermaid story.mmd --cypher story.cypher
```

```text
[+] alerts: 2
    RL-009  medium   T1140      base64 decoding: base64 -d
    RL-003  critical T1071      bash opened outbound connection to 192.168.2.6:443 (reverse shell / C2)
[*] pivot: RL-003 on bash[17806]
[*] root cause(s): ['192.168.2.6:8888', '192.168.2.6:1389']
```

Other entry points:

```bash
rootline analyze capture.log --ioc 203.0.113.66     # pivot on an IOC instead of the top alert
rootline analyze capture.log --iforest              # also rank process vertices with IsolationForest
rootline verify events.jsonl --head <hash>          # exit code 2 if the record was altered
rootline serve --fuse a.json b.json                 # API + replay UI on http://127.0.0.1:8000 ([api] extra)
```

## Docker

```bash
docker run --rm -p 8000:8000 ghcr.io/rakshit-737/rootline:latest   # UI preloaded with Log4Shell
docker compose up                                                  # UI + Neo4j browser on :7474
```

## Reproduce the benchmarks

```bash
pip install -e ".[dev,bench]"
python scripts/download_data.py          # ~0.4 GB into ../../datasets/rootline (or $ROOTLINE_DATA)
python -m pytest -q -m realdata
python scripts/bench.py                  # regenerates results/
```
