# Contributing to ROOTLINE

Thanks for helping. ROOTLINE is small on purpose: every step of the reconstruction
should be explainable as graph edges. Please keep changes in that spirit.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev,bench]"
python -m pytest -q                                # unit + fixture tests; realdata tests skip without data
python -m ruff check src tests scripts repro
mkdocs build --strict                              # docs (pip install -r requirements-docs.txt); docs/hooks.py builds the demo
```

Optional, for the real-data benchmarks:

```bash
python scripts/download_data.py        # ~0.74 GB into $ROOTLINE_DATA (default ~/.cache/rootline)
python -m pytest -q -m realdata        # tests that need the downloads
python scripts/bench.py                # regenerates results/ - commit the diff with your change
```

`make` targets (`make test`, `make bench`, ...) wrap the same commands.

## Ground rules

- **The core stays standard-library only.** New heavy dependencies go behind an
  extra (`ml`, `api`, `stix`, `bench`) with `pytest.importorskip` in their tests.
  CI checks this with the `core-no-extras` job.
- **Parsers treat input as hostile.** Bound sizes, reject DTDs, and skip and count
  malformed records instead of raising. Add a test for each new malformed case.
- **No live malware, no exploit code, no scanning.** Fixtures are event logs. Add
  new public excerpts under `tests/fixtures/` (each file under 1 MB, attribution in
  `SOURCES.txt`). Datasets themselves are never committed. Add them to
  `scripts/data_manifest.json` with a SHA-256.
- **Rules need a reason and a counter-example.** Each new rule maps to an ATT&CK
  technique and has a test that shows it firing, plus one that shows a benign
  look-alike staying quiet. If you read benchmark captures while writing a rule,
  add those captures to the `dev` split. The `sealed` split was scored once with the
  frozen v0.3 rules (docs/protocol.md); any rule change is a new version, and its
  sealed numbers must then be labelled in-sample.
- **Report results honestly.** If a change moves a benchmark number, update
  `results/` and the README table in the same PR, including numbers that got worse.

## Commits and PRs

- Use conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`,
  `refactor:`, `ci:`, `build:`. Keep each one small and logical.
- Record design decisions in `docs/adr/NNNN-title.md`. Copy the format of the
  existing ADRs.
- Add a line to `CHANGELOG.md` under *Unreleased*.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open public issues for
vulnerabilities in the parsers.
