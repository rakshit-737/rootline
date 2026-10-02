PY ?= python
export PYTHONPATH := src

.PHONY: install test lint data data-all bench ablation docs demo serve clean

install:
	$(PY) -m pip install -e ".[dev,bench]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check src tests scripts repro

data:            ## ATLAS S1 zip + OTRF + Splunk dev/dev2 (~0.74 GB, outside the repo)
	$(PY) scripts/download_data.py

data-all:        ## + ATLAS M1 (multi-host), S2-S4 (repro) and the sealed Splunk split
	$(PY) scripts/download_data.py --all

bench:           ## regenerate results/ (RESULTS.md, JSON, figures)
	$(PY) scripts/bench.py

ablation:        ## ATLAS ablation (S1-S4 + M hosts) -> results/ablation.json
	$(PY) scripts/ablation.py

docs:            ## build the docs site (docs/hooks.py generates the demo, figures and CLI page)
	$(PY) -m pip install -r requirements-docs.txt
	$(PY) -m mkdocs build --strict

demo:
	$(PY) -m rootline.cli demo --outdir out

serve:
	$(PY) -m rootline.cli serve --fuse tests/fixtures/log4shell_sysmon.json tests/fixtures/log4shell_auoms.json

clean:
	rm -rf out .pytest_cache build *.egg-info src/*.egg-info
