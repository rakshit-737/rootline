PY ?= python
export PYTHONPATH := src

.PHONY: install test demo lint clean

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

demo:
	$(PY) -m rootline.cli demo --outdir out

clean:
	rm -rf out .pytest_cache build *.egg-info src/*.egg-info
