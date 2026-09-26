PY ?= python
export PYTHONPATH := src

.PHONY: install test lint data data-all bench demo serve clean

install:
	$(PY) -m pip install -e ".[dev,bench]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check src tests scripts

data:            ## ATLAS S1-S4 + OTRF + Splunk dev/holdout (~0.4 GB, outside the repo)
	$(PY) scripts/download_data.py

data-all:        ## + optional ATLAS multi-host M1-M6 (~62 MB more)
	$(PY) scripts/download_data.py --all

bench:           ## regenerate results/ (RESULTS.md, JSON, figures)
	$(PY) scripts/bench.py

demo:
	$(PY) -m rootline.cli demo --outdir out

serve:
	$(PY) -m rootline.cli serve tests/fixtures/log4shell_sysmon.json

clean:
	rm -rf out .pytest_cache build *.egg-info src/*.egg-info
